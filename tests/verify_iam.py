#!/usr/bin/env python3
"""Verifier for the IAM policy engine task.

usage: verify_iam.py <run-dir> <details.json>

Generates fresh scenarios (snapshot + queries), answers them with the reference
engine, runs /app/iamctl on each as the unprivileged agent user, and requires
every answer to match exactly. Exit 0 iff all scenarios match.
"""
import json
import os
import random
import resource
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_scenarios  # noqa: E402
import reference_engine as ref  # noqa: E402

RUN_DIR, DETAILS = sys.argv[1], sys.argv[2]
SEED = int(os.environ.get("FSWE_SEED") or int.from_bytes(os.urandom(6), "big"))
N_SCENARIOS = 6
TIMEOUT = 300


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (4 << 30, 4 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def norm(a):
    if not isinstance(a, dict) or "id" not in a:
        return None
    for k in ("decision", "roles", "principals"):
        if k in a:
            v = a[k]
            return (k, tuple(v) if isinstance(v, list) else v)
    return None


def main():
    master = random.Random(SEED)
    log = {"seed": SEED, "scenarios": []}
    ok_all = True
    for i in range(N_SCENARIOS):
        seed = master.getrandbits(48)
        snap, queries = gen_scenarios.make_scenario(seed, engine=ref)
        es = ref.Snapshot(json.loads(json.dumps(snap)))
        expected = {q["id"]: norm(ref.answer(es, q)) for q in queries}
        sp, qp = os.path.join(RUN_DIR, f"snapshot{i}.json"), os.path.join(RUN_DIR, f"queries{i}.jsonl")
        with open(sp, "w") as fh:
            json.dump(snap, fh, indent=1)
        with open(qp, "w") as fh:
            for q in queries:
                fh.write(json.dumps(q) + "\n")
        for p in (sp, qp):
            os.chmod(p, 0o644)
        rec = {"scenario_seed": seed, "queries": len(queries)}
        try:
            proc = subprocess.run(["/app/iamctl", sp, qp], capture_output=True, timeout=TIMEOUT,
                                  user="agent", group="agent", extra_groups=[], preexec_fn=limits,
                                  env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/agent", "LC_ALL": "C.UTF-8"},
                                  cwd=RUN_DIR)
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            rc, out, err = "timeout", b"", b""
        except OSError as e:
            rc, out, err = f"cannot run: {e}", b"", b""
        rec["exit"] = rc
        got = {}
        bad_lines = 0
        for line in out.decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            try:
                a = json.loads(line)
            except ValueError:
                bad_lines += 1
                continue
            n = norm(a)
            if n is None:
                bad_lines += 1
                continue
            got[a["id"]] = n
        wrong = [qid for qid in expected if got.get(qid) != expected[qid]]
        extra = [qid for qid in got if qid not in expected]
        rec.update({"wrong": len(wrong), "missing": sum(1 for q in expected if q not in got),
                    "extra": len(extra), "bad_lines": bad_lines, "stderr_tail": err.decode("utf-8", "replace")[-400:]})
        types = {q["id"]: q["type"] for q in queries}
        rec["wrong_by_type"] = {t: sum(1 for w in wrong if types[w] == t) for t in ("authorize", "reachable_roles", "who_can")}
        log["scenarios"].append(rec)
        if rc != 0 or wrong or extra or bad_lines:
            ok_all = False
        print(f"scenario {i}: queries={len(queries)} exit={rc} wrong={len(wrong)} {rec['wrong_by_type']} extra={len(extra)} bad_lines={bad_lines}")
    with open(DETAILS, "w") as fh:
        json.dump(log, fh, indent=1)
    print(f"seed={SEED} result={'PASS' if ok_all else 'FAIL'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # a verifier crash must never read as a pass
        print("VERIFIER ERROR", repr(exc))
        sys.exit(3)
