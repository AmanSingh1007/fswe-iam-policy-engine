# Policy engine specification

This document is normative. Where it differs from AWS's own behaviour, this document wins. Every rule
below is applied exactly as written; nothing outside it is assumed.

## 1. Inputs

### 1.1 Snapshot

```json
{
  "organization": null | {
    "id": "o-xxxxxxxxxx",
    "management_account": "111111111111",
    "policies": { "<scp name>": <policy document>, ... },
    "root": <org node>
  },
  "accounts": {
    "<12-digit account id>": {
      "users":  { "<name>": { "tags": {..}, "groups": ["<group>"], "policies": [<doc>],
                              "managed_policies": ["<policy arn>"], "permissions_boundary": "<policy arn>" } },
      "groups": { "<name>": { "policies": [<doc>], "managed_policies": ["<policy arn>"] } },
      "roles":  { "<name>": { "path": "/team/", "tags": {..}, "trust_policy": <doc>, "policies": [<doc>],
                              "managed_policies": ["<policy arn>"], "permissions_boundary": "<policy arn>" } },
      "managed_policies": { "<policy arn>": <doc> },
      "resources": [ { "arn": "<arn>", "tags": {..}, "policy": <doc> } ]
    }
  },
  "aws_managed_policies": { "<policy arn>": <doc> }
}
```

An org node is `{"id": .., "scps": ["<scp name>"], "accounts": [{"id": "<account>", "scps": [..]}],
"children": [<org node>]}`. Any field other than ids may be missing; a missing list or map is empty, a
missing `path` is `/`, a missing `permissions_boundary` means the principal has none.

### 1.2 Queries

JSON lines. Every query has an `id`. There are three types.

```json
{"id": "q1", "type": "authorize", "principal": <principal>, "action": "s3:GetObject",
 "resource": "arn:aws:s3:::bucket/key", "context": {"aws:SourceIp": "10.0.0.1", ...}}
{"id": "q2", "type": "reachable_roles", "principal": <principal>, "session_name": "hop", "context": {..}}
{"id": "q3", "type": "who_can", "action": "kms:Decrypt", "resource": "<arn>", "context": {..}}
```

A principal is one of

```json
{"type": "user", "account": "<acct>", "name": "<user>"}
{"type": "role_session", "account": "<acct>", "role": "<role>", "session_name": "<name>",
 "session_policy": <doc>, "session_tags": {"<key>": "<value>"}}
{"type": "root", "account": "<acct>"}
```

`session_policy` and `session_tags` are optional. Context values are strings or lists of strings.
Queries only name users, roles and accounts that exist in the snapshot.

### 1.3 Output

One JSON object per query, one per line, on stdout:

```json
{"id": "q1", "decision": "Allow" | "ExplicitDeny" | "ImplicitDeny"}
{"id": "q2", "roles": ["<role arn>", ...]}          // sorted ascending, no duplicates
{"id": "q3", "principals": ["<arn>", ...]}          // sorted ascending, no duplicates
```

## 2. Names

* User ARN: `arn:aws:iam::<acct>:user/<name>`.
* Role ARN: `arn:aws:iam::<acct>:role<path><name>` (path starts and ends with `/`, e.g.
  `arn:aws:iam::111111111111:role/team/deploy`).
* Role session ARN: `arn:aws:sts::<acct>:assumed-role/<role name>/<session name>`. **The role path is
  not part of it.**
* Account root ARN: `arn:aws:iam::<acct>:root`.

The *principal ARN* of a user or root is its own ARN; for a role session it is the role's ARN (with
path). The *requester ARN* is the user ARN, the role session ARN, or the root ARN.

## 3. Policy documents

A document is an object with an optional `Version` and a `Statement` that is one statement object or
a list of them. Anything that is not a statement object is ignored. A statement applies only if its
`Effect` is exactly `Allow` or `Deny`.

### 3.1 Version and policy variables

Policy variables are resolved **only** in documents whose `Version` is exactly `"2012-10-17"`. In any
other document (other version string, or no `Version`), `${...}` is ordinary text.

Variables are resolved in the `Resource`/`NotResource` patterns and in every condition value (all
operators except `Null`). Nowhere else (not in `Action`, `NotAction`, `Principal`, condition keys).

A variable is `${<body>}` where body (trimmed) is one of:

* `*`, `?` or `$`: the literal character. It never acts as a wildcard.
* `<key>`: the request context value of `<key>` (case-insensitive key lookup, §5.1).
* `<key>, '<default>'`: as above, but `<default>` is used when the key has no value.

A key "has a value" when the context holds a string for it, or a list of exactly one string (that
string is the value). Otherwise (absent, or a list of zero or several strings) it has no value. A
variable whose key has no value and no default is *unresolved*. A substituted value is always matched
literally: wildcard characters in it are not wildcards.

A pattern or condition value containing an unresolved variable matches nothing (see §4 and §6).

### 3.2 Statement matching for one request

Given an action, a resource ARN and a request context, a statement *matches* when all of:

1. **Action.** If `Action` is present (string or list), the action matches at least one entry. Else,
   if `NotAction` is present, the action matches none of its entries. Else the statement never
   matches. Action matching: whole-string wildcard match, `*` = any sequence (possibly empty), `?` =
   any one character, **case-insensitive**.
2. **Resource.** If `Resource` is present, the resource matches at least one entry (§4). Else, if
   `NotResource` is present, it matches none. Else: the statement matches only if it belongs to a
   resource-based policy (§7.2: a resource policy or a trust policy), in which case it matches the
   resource the policy is attached to; in any other policy the statement never matches.
3. **Condition.** The `Condition` block (if any) evaluates to true (§6).

If both `Action` and `NotAction` are present, only `Action` is used; likewise `Resource` over
`NotResource`.

## 4. ARN pattern matching

Used for `Resource`, `NotResource`, `ArnEquals`, `ArnLike`, `ArnNotEquals`, `ArnNotLike`.

* A pattern that is exactly one `*` written in the policy text matches any string. (A `*` that comes
  from `${*}` or from a substituted variable value is a literal character, so it does not.)
* Otherwise both pattern and value are split into segments on `:`. A pattern with fewer than six
  segments matches nothing, and a value with fewer than six segments matches nothing. A colon that comes from a substituted
  variable value does not split segments. If the pattern has more than six segments, everything from
  the sixth onward (with its colons) is the sixth segment.
* Each pattern segment must match the corresponding value segment as a whole-string wildcard match
  (`*` any sequence including `/` and `:`, `?` one character), **case-sensitive**.

`ArnEquals` and `ArnLike` behave identically (both honour wildcards).

## 5. Request context

### 5.1 Keys

Context keys are case-insensitive. A key whose value is an empty string or an empty list is absent.
The engine builds the context for each request from the query's `context`, then **removes** any
supplied key that is listed below or that starts with `aws:PrincipalTag/` or `aws:ResourceTag/`, then
sets:

| Key | Value |
|---|---|
| `aws:PrincipalAccount` | principal's account |
| `aws:PrincipalArn` | principal ARN (§2) |
| `aws:PrincipalType` | `User`, `AssumedRole` or `Account` (root) |
| `aws:username` | user name; absent for role sessions and root |
| `aws:PrincipalTag/<k>` | user tags; for a role session the role's tags overlaid by the session tags (tag keys compared case-insensitively, session tag wins) |
| `aws:ResourceAccount` | resource account (§7.1) |
| `aws:ResourceTag/<k>` | tags of the registered resource or role being accessed (§7.1) |
| `aws:PrincipalOrgID` | the organization id, if the principal's account appears anywhere in the organization tree or is the management account; otherwise absent |

## 6. Conditions

A `Condition` block maps operator names to `{key: value-or-list}` maps. The block is true iff every
operator entry is true; an operator entry is true iff every key in it is true. A block that is not an
object, or an operator entry that is not an object, is false.

Operator names are case-sensitive and have the form `[ForAnyValue:|ForAllValues:]<op>[IfExists]`.
Policy values are normalised to strings: `true`/`false` JSON booleans become `"true"`/`"false"`,
numbers become their decimal text (`10` → `"10"`); other JSON types are dropped. An unknown operator
makes the block false.

### 6.1 `Null`

`{"Null": {"k": "true"}}` is true iff `k` is absent; `"false"` iff present (values compared
case-insensitively; with a list, true if any value is satisfied). `Null` with a set qualifier or
`IfExists` makes the block false.

### 6.2 Other operators

Positive base operators and their single-value test `T(v, p)` for context value `v` and policy value
`p` (after variable substitution; a policy value containing an unresolved variable makes `T` false
for it):

| Operator | `T(v, p)` |
|---|---|
| `StringEquals` | `v == p` |
| `StringEqualsIgnoreCase` | equal ignoring case |
| `StringLike` | `v` matches wildcard pattern `p` (`*`, `?`), case-sensitive |
| `NumericEquals`, `NumericLessThan`, `NumericLessThanEquals`, `NumericGreaterThan`, `NumericGreaterThanEquals` | numeric comparison `v ⋄ p`; false if either is not a decimal number: optional sign, then digits with an optional fraction (`12`, `12.`, `12.5`, `.5`), then an optional exponent (`e`/`E`, optional sign, digits), nothing else (no spaces) |
| `DateEquals`, `DateLessThan`, `DateLessThanEquals`, `DateGreaterThan`, `DateGreaterThanEquals` | compare instants; each side is an integer (epoch seconds) or ISO 8601 date/date-time (`Z` or `±HH:MM` offset; no offset means UTC); false if either does not parse |
| `Bool` | equal ignoring case |
| `IpAddress` | `v` is an IP address inside CIDR `p` (host bits in `p` are ignored); false if either does not parse |
| `ArnEquals`, `ArnLike` | §4 match of pattern `p` against `v` |

Negated operators are `StringNotEquals`, `StringNotEqualsIgnoreCase`, `StringNotLike`,
`NumericNotEquals`, `DateNotEquals`, `NotIpAddress`, `ArnNotEquals`, `ArnNotLike`; their base is the
corresponding positive operator.

For one key with policy values `P`, define for each context value `v`:
`M(v) = any(T(v, p) for p in P)`, and `M'(v) = not M(v)` for a negated operator, else `M(v)`.

Let `V` be the key's context values (a string is a one-element list).

* `V` empty (key absent):
  * `ForAllValues:` → **true**;
  * `ForAnyValue:` → true only with `IfExists`, else false;
  * no qualifier → true if `IfExists` or the operator is negated, else false.
* `V` non-empty:
  * `ForAllValues:` → `all(M'(v) for v in V)`;
  * otherwise (`ForAnyValue:` or no qualifier) → `any(M'(v) for v in V)`.

## 7. Authorization

### 7.1 The resource

* If the resource ARN equals the ARN of a role in the snapshot, the resource account is that role's
  account, its resource-based policy is the role's `trust_policy` (for every action), and its tags are
  the role's tags.
* Else if it equals the `arn` of an entry in some account's `resources`, the account is that account,
  the policy is the entry's `policy` (if any), the tags its `tags`.
* Else the resource is unregistered: its account is the 5th ARN segment if that is 12 digits, otherwise
  the principal's account; it has no policy and no tags.

The resource is in the *same account* when the resource account equals the principal's account.

### 7.2 Policies that apply to a principal

* **Identity policies.** User: its inline `policies`, its `managed_policies`, and for each of its
  `groups` that exists in its account, the group's inline and managed policies. Role session: the
  role's inline and managed policies. Root: none.
  Managed policy ARNs are looked up in `aws_managed_policies` and then in every account's
  `managed_policies`; an ARN that is not found is ignored. A group that does not exist is ignored.
* **Permissions boundary** (users and roles): the managed policy named by `permissions_boundary`. If it
  is set but not found, the boundary is a document with no statements (it allows nothing).
* **Session policy** (role sessions): the query's `session_policy`, if present.
* **SCPs**: if there is an organization, the principal's account appears in its tree, and it is **not**
  the management account, the SCP *levels* are, in order: the root node, each OU on the path to the
  account, and the account entry itself. Each level is the list of SCP documents named in its `scps`
  (an unknown name contributes a document with no statements). Otherwise there are no SCP levels.
* **Resource-based policy**: per §7.1.

### 7.3 Matching principals in resource-based policies

A statement in a resource-based policy applies to the requester according to `Principal` or
`NotPrincipal`; a statement with neither applies to no one. Entries are taken from `"*"` (the value
itself) or from the `AWS` member of an object (string or list); other members (`Service`, …) match no
requester. An entry matches the requester with a *kind*:

| Entry | Matches | Kind |
|---|---|---|
| `*` | anyone | direct |
| 12-digit account id, or `arn:aws:iam::<acct>:root` | any requester in that account | `direct` for the root requester, otherwise `account` |
| exactly the requester ARN (user ARN, role session ARN, root ARN) | that requester | direct |
| exactly a role ARN (with path) | any session of that role | role |

No other wildcards are allowed in entries; comparison is exact and case-sensitive.

* `Principal`: the statement applies with the strongest kind among matching entries
  (direct > role > account); it does not apply if none match.
* `NotPrincipal`: the statement applies (kind direct) iff no entry matches, where for this purpose **a
  role ARN entry does not match the role's sessions** (only a session ARN, account or `*` entry can
  exclude a session).

### 7.4 Decision for `authorize`

Evaluate in this order; the first rule that decides wins.

1. **Explicit deny.** `ExplicitDeny` if any `Deny` statement matches (§3.2) in: an identity policy,
   the boundary, the session policy, any SCP at any level, or the resource-based policy (where the
   statement must also apply to the requester under §7.3, any kind).
2. **SCPs.** For each SCP level: if no `Allow` statement in that level's documents matches,
   `ImplicitDeny`. (A level with no documents therefore denies.)
3. Let
   * `identity` = the principal is root, or an `Allow` matches in an identity policy;
   * `boundary_ok` = no boundary, or an `Allow` matches in the boundary;
   * `session_ok` = no session policy, or an `Allow` matches in it;
   * `grant` = the strongest kind among `Allow` statements of the resource-based policy that match and
     apply to the requester, or none.
4. **Same account:**
   * root requester → `Allow`;
   * `grant` is direct → `Allow` (boundary and session policy do not limit it);
   * otherwise `Allow` iff (`identity` or `grant` is role) and `boundary_ok` and `session_ok`;
   * else `ImplicitDeny`. (A grant of kind account adds nothing on its own.)
5. **Different accounts:** `Allow` iff `identity` and `boundary_ok` and `session_ok` and `grant` is not
   none; else `ImplicitDeny`.

## 8. `reachable_roles`

Starting from the query principal, repeatedly assume roles. From a requester `R`, role `X` (any role
in the snapshot) is reachable in one hop iff `authorize(R, "sts:AssumeRole", <X's role ARN>,
context)` is `Allow`, using the query's `context` for every hop. The requester after a hop into `X`
is a session of `X` named by the query's `session_name` (default `hop`), with no session policy and no
session tags. The answer is the set of role ARNs reachable in one or more hops from the starting
principal (the starting principal's own role is included only if reachable that way).

## 9. `who_can`

Over every user and every role in every account: a user is included (by user ARN) if
`authorize(user, action, resource, context)` is `Allow`; a role is included (by **role ARN**) if a
session of it named `who`, with no session policy or tags, gets `Allow`. Account roots are never
listed.
