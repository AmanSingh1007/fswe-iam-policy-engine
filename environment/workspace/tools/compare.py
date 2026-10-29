#!/usr/bin/env python3
"""Run ./iamctl on an example directory and diff against expected.jsonl.

usage: python3 tools/compare.py examples/ex1 [examples/ex2 ...]
"""
import json
import subprocess
import sys

for d in sys.argv[1:]:
    out = subprocess.run(["./iamctl", f"{d}/snapshot.json", f"{d}/queries.jsonl"], capture_output=True, text=True)
    got = {}
    for line in out.stdout.splitlines():
        if line.strip():
            a = json.loads(line)
            got[a["id"]] = a
    queries = {json.loads(l)["id"]: json.loads(l) for l in open(f"{d}/queries.jsonl") if l.strip()}
    wrong = 0
    for line in open(f"{d}/expected.jsonl"):
        if not line.strip():
            continue
        e = json.loads(line)
        if got.get(e["id"]) != e:
            wrong += 1
            if wrong <= 10:
                q = queries[e["id"]]
                print(f"  {e['id']} {q['type']} {q.get('action', '')} {q.get('resource', '')}\n    expected {e}\n    got      {got.get(e['id'])}")
    print(f"{d}: {len(queries) - wrong}/{len(queries)} correct (exit {out.returncode})")
    if out.stderr.strip():
        print("  stderr:", out.stderr.strip()[-300:])
