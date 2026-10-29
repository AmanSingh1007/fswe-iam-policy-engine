# Cloud IAM authorization engine and access analyzer

A security team wants an offline engine that answers "is this request allowed, and why not?" for a
snapshot of a cloud organization: its accounts, users, groups, roles, managed policies, permissions
boundaries, service control policies (SCPs), resource policies and role trust policies. They also
want two analyses on top of it: which roles a principal can reach by chaining role assumptions, and
which principals can perform a given action on a given resource.

Build it as the executable `/app/iamctl`:

```
/app/iamctl SNAPSHOT.json QUERIES.jsonl > ANSWERS.jsonl
```

The input formats, the output format and **every** evaluation rule are defined in `/app/SPEC.md`.
That document is normative: where it differs from how a real cloud provider behaves, follow the
document. Read it in full; the rules interact, and many of them are easy to get subtly wrong.

`/app/examples/ex1..ex3` each hold a snapshot, a query file and the expected answers.
`python3 /app/tools/compare.py examples/ex1` runs your `iamctl` against one and shows mismatches.
The examples are a sample only: they do not exercise every rule in the specification.

## How it is graded

New organizations and query sets are generated at grading time (the same input format, different
accounts, names, policies and contexts, and including corner cases that the examples do not
contain). `/app/iamctl` is run once per scenario; each run must exit 0 within 300 seconds, write
exactly one well-formed answer line per query, and every answer must be exactly right: the
decision string for `authorize`, and the exact sorted ARN list for `reachable_roles` and `who_can`.
The task is complete only if every answer in every scenario is correct.

## Constraints

- `/app/iamctl` may be a script or a binary; Python 3.13 (standard library only) is installed.
  Everything it needs must live under `/app`.
- The machine has no network access.
- It runs as an unprivileged user with the snapshot and query files as its only input.
