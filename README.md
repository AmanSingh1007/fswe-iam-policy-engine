# iam-policy-engine — a FrontierSWE-style cybersecurity task

**Category:** Cybersecurity — IAM and cloud security (defensive authorization analysis)

## What the agent must do

Build `/app/iamctl`, an offline authorization engine and access analyzer for a snapshot of a cloud
organization (accounts, users, groups, roles, managed policies, permissions boundaries, SCPs, resource
policies, role trust policies). Given `SNAPSHOT.json` and `QUERIES.jsonl` it answers, one JSON line per
query:

- `authorize` — `Allow`, `ExplicitDeny` or `ImplicitDeny` for a principal (user, role session with
  optional session policy/tags, or account root), action, resource and request context;
- `reachable_roles` — every role reachable by chaining `sts:AssumeRole`;
- `who_can` — every user and role that can perform an action on a resource.

The full semantics are fixed by the normative `environment/workspace/SPEC.md` (shipped as
`/app/SPEC.md`): context construction, statement matching, ARN segment wildcards, policy variables,
condition operators with set qualifiers and `IfExists`, principal matching kinds, SCP levels, and the
same-/cross-account decision procedure. Three worked examples (snapshot, queries, expected answers)
and a diff tool are included; they deliberately do not contain the planted corner cases.

## How the verifier evaluates it

`tests/test.sh` kills leftover agent processes, makes `/tests` root-only, and runs
`tests/verify_iam.py`, which:

1. generates **six fresh scenarios** from a new random seed (`tests/gen_scenarios.py`): random
   four/five-account organizations with OU trees and SCPs, users/groups/roles with policies drawn from
   templates aimed at every rule, resource and trust policies, plus deterministic **corner-case
   fixtures** (session-ARN grants vs boundaries, `NotPrincipal` role vs session, Version 2008 literal
   variables, `${*}`, variable defaults, unresolved variables, per-level SCPs, `ArnEquals` wildcards,
   `ForAllValues` on missing keys, unknown boundaries, multi-hop role chains through session ARNs);
2. answers ~340 queries per scenario with the hidden reference engine (`tests/reference_engine.py`);
   authorize queries are stratified to ~40% Allow / 20% ExplicitDeny / 40% ImplicitDeny;
3. runs `/app/iamctl` on each scenario as the unprivileged `agent` user (300 s, 4 GiB) and requires
   every answer to match exactly, with exit 0 and no missing, extra or malformed lines.

`reward.txt` is 1 only if all six scenarios match exactly, else 0.

A mutation suite was used to confirm coverage: 18 single-rule mis-implementations of the reference
(session ARN with role path, boundary limiting direct grants, account-root treated as direct grant,
`ForAllValues` false on missing keys, negated operators false on missing keys, variables resolved in
any version, `NotPrincipal` role matching sessions, SCPs applied to the management account,
case-sensitive actions, `${*}` as wildcard, SCP levels unioned, requester-supplied principal tags
honoured, `ArnEquals` exact, empty SCP level allowing, unknown boundary ignored, cross-account without
identity allow, unresolved variables kept literally, resource tags ignored) are each caught in every
one of six scenarios.

## Estimated completion time

About **12 hours** for a strong security engineer: ≈2 h to digest the spec, ≈5 h for the evaluator
(conditions, variables, ARN matching, principal kinds, decision procedure), ≈1 h for the two analyses,
≈4 h of testing against the examples and self-built edge cases for the rules the examples do not
cover.

## Layout

```
instruction.md            agent-facing prompt
task.toml                 Harbor/FrontierSWE task config (72000 s agent budget, no network)
environment/Dockerfile    pinned python:3.13-slim, non-root `agent` user
environment/workspace/    starting /app: SPEC.md, iamctl stub, examples/, tools/compare.py
solution/solve.sh         reference solution (installs solution/iam_engine.py behind /app/iamctl)
solution/iam_engine.py    reference engine
tests/                    verifier (test.sh, verify_iam.py, gen_scenarios.py, reference_engine.py)
```

## Running

```
python3 frontierswe-check.py path/to/fswe-iam-policy-engine
harbor run -p path/to/fswe-iam-policy-engine -a oracle   # Mean: 1.000
harbor run -p path/to/fswe-iam-policy-engine -a nop      # Mean: 0.000
```
