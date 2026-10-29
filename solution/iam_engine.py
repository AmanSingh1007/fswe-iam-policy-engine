#!/usr/bin/env python3
"""Reference implementation of the policy engine described in /app/SPEC.md.

usage: iam_engine.py SNAPSHOT.json QUERIES.jsonl   (answers as JSON lines on stdout)
"""
import datetime
import ipaddress
import json
import re
import sys
from functools import lru_cache

V2012 = "2012-10-17"
VAR_RE = re.compile(r"\$\{([^}]*)\}")
NEGATED = {
    "StringNotEquals": "StringEquals", "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
    "StringNotLike": "StringLike", "NumericNotEquals": "NumericEquals", "DateNotEquals": "DateEquals",
    "NotIpAddress": "IpAddress", "ArnNotEquals": "ArnEquals", "ArnNotLike": "ArnLike",
}
POSITIVE = {
    "StringEquals", "StringEqualsIgnoreCase", "StringLike", "NumericEquals", "NumericLessThan",
    "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals", "DateEquals", "DateLessThan",
    "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals", "Bool", "IpAddress", "ArnEquals", "ArnLike",
}
ACCOUNT_RE = re.compile(r"^\d{12}$")


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def scalar_str(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return v if isinstance(v, str) else None


# ---------------------------------------------------------------- patterns

class Unresolved(Exception):
    pass


def resolve(text, ctx, version):
    """Substitute policy variables. Returns list of (chunk, literal) pieces:
    literal=True chunks never act as wildcards. Raises Unresolved."""
    if version != V2012:
        return [(text, False)]
    pieces, pos = [], 0
    for m in VAR_RE.finditer(text):
        if m.start() > pos:
            pieces.append((text[pos:m.start()], False))
        body = m.group(1).strip()
        if body in ("*", "?", "$"):
            pieces.append((body, True))
        else:
            default = None
            dm = re.fullmatch(r"([^,]+?)\s*,\s*'([^']*)'", body)
            key = body
            if dm:
                key, default = dm.group(1).strip(), dm.group(2)
            val = ctx.get(key.lower())
            if isinstance(val, list):
                val = val[0] if len(val) == 1 else None
            if val is None or val == "":
                if default is None:
                    raise Unresolved(key)
                val = default
            pieces.append((val, True))
        pos = m.end()
    if pos < len(text):
        pieces.append((text[pos:], False))
    return pieces


def pieces_plain(pieces):
    return "".join(c for c, _ in pieces)


def pieces_regex(pieces):
    out = []
    for chunk, literal in pieces:
        if literal:
            out.append(re.escape(chunk))
        else:
            for ch in chunk:
                out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return "".join(out)


@lru_cache(maxsize=200000)
def _compile(rx, flags):
    return re.compile(rx, flags | re.S)


def wild_match(pieces, value, ignore_case=False):
    return _compile(pieces_regex(pieces), re.I if ignore_case else 0).fullmatch(value) is not None


def split_arn(s):
    parts = s.split(":", 5)
    return parts if len(parts) == 6 else None


def arn_match(pattern, value, ctx, version):
    """Segment-wise wildcard match of an ARN pattern; '*' alone matches anything."""
    try:
        pieces = resolve(pattern, ctx, version)
    except Unresolved:
        return False
    if pieces_plain(pieces) == "*" and not pieces[0][1]:
        return True
    # split pieces into the six segments on unescaped (non-literal) colons
    segs, cur = [], []
    for chunk, literal in pieces:
        if literal:
            cur.append((chunk, True))
            continue
        parts = chunk.split(":")
        for i, p in enumerate(parts):
            if i > 0:
                segs.append(cur)
                cur = []
            if p:
                cur.append((p, False))
    segs.append(cur)
    if len(segs) < 6:
        return False
    if len(segs) > 6:   # colons in the resource segment are part of it
        tail = []
        for i, s in enumerate(segs[5:]):
            if i:
                tail.append((":", True))
            tail.extend(s)
        segs = segs[:5] + [tail]
    vals = split_arn(value)
    if vals is None:
        return False
    return all(wild_match(p, v) for p, v in zip(segs, vals))


def action_match(pattern, action):
    pieces = [(pattern, False)]
    return wild_match(pieces, action, ignore_case=True)


# --------------------------------------------------------------- conditions

def parse_date(s):
    try:
        if re.fullmatch(r"-?\d+", s):
            return float(s)
        d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return d.timestamp()
    except (ValueError, OverflowError):
        return None


def parse_num(s):
    try:
        if not re.fullmatch(r"[-+]?(\d+(\.\d*)?|\.\d+)([eE][-+]?\d+)?", s):
            return None
        return float(s)
    except ValueError:
        return None


def positive_test(op, v, pv_raw, ctx, version):
    """op(v, policy value) for one context value v and one policy value."""
    if op in ("ArnEquals", "ArnLike"):
        return arn_match(pv_raw, v, ctx, version)
    try:
        pieces = resolve(pv_raw, ctx, version)
    except Unresolved:
        return False
    if op == "StringLike":
        return wild_match(pieces, v)
    p = pieces_plain(pieces)
    if op == "StringEquals":
        return v == p
    if op == "StringEqualsIgnoreCase":
        return v.lower() == p.lower()
    if op == "Bool":
        return v.lower() == p.lower()
    if op.startswith("Numeric"):
        a, b = parse_num(v), parse_num(p)
        if a is None or b is None:
            return False
        return {"NumericEquals": a == b, "NumericLessThan": a < b, "NumericLessThanEquals": a <= b,
                "NumericGreaterThan": a > b, "NumericGreaterThanEquals": a >= b}[op]
    if op.startswith("Date"):
        a, b = parse_date(v), parse_date(p)
        if a is None or b is None:
            return False
        return {"DateEquals": a == b, "DateLessThan": a < b, "DateLessThanEquals": a <= b,
                "DateGreaterThan": a > b, "DateGreaterThanEquals": a >= b}[op]
    if op == "IpAddress":
        try:
            return ipaddress.ip_address(v) in ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    return False


def condition_block(cond, ctx, version):
    if not cond:
        return True
    if not isinstance(cond, dict):
        return False
    for opname, kv in cond.items():
        if not isinstance(kv, dict):
            return False
        qual = None
        op = opname
        for q in ("ForAnyValue:", "ForAllValues:"):
            if op.startswith(q):
                qual, op = q[:-1], op[len(q):]
        if_exists = False
        if op.endswith("IfExists") and op != "IfExists":
            if_exists, op = True, op[:-len("IfExists")]
        if op == "Null":
            if qual or if_exists:
                return False
            for key, pvals in kv.items():
                present = ctx.get(key.lower()) not in (None, [], "")
                ok = False
                for pv in as_list(pvals):
                    s = scalar_str(pv)
                    if s is not None and s.lower() == "true" and not present:
                        ok = True
                    if s is not None and s.lower() == "false" and present:
                        ok = True
                if not ok:
                    return False
            continue
        neg = op in NEGATED
        base = NEGATED.get(op, op)
        if base not in POSITIVE:
            return False
        for key, pvals in kv.items():
            raw = ctx.get(key.lower())
            vals = [raw] if isinstance(raw, str) else list(raw) if isinstance(raw, list) else []
            vals = [v for v in vals if isinstance(v, str)]
            pvs = [scalar_str(p) for p in as_list(pvals)]
            pvs = [p for p in pvs if p is not None]

            def t(v):
                r = any(positive_test(base, v, p, ctx, version) for p in pvs)
                return (not r) if neg else r

            if not vals:
                if qual == "ForAllValues":
                    res = True
                elif qual == "ForAnyValue":
                    res = if_exists
                else:
                    res = True if (if_exists or neg) else False
            elif qual == "ForAllValues":
                res = all(t(v) for v in vals)
            else:
                res = any(t(v) for v in vals)
            if not res:
                return False
    return True


# ---------------------------------------------------------------- snapshot

class Snapshot:
    def __init__(self, data):
        self.d = data
        self.accounts = data.get("accounts", {})
        self.aws_managed = data.get("aws_managed_policies", {})
        self.org = data.get("organization")
        self.resources = {}
        self.roles_by_arn = {}
        for acc, a in sorted(self.accounts.items()):
            for r in a.get("resources", []):
                self.resources[r["arn"]] = (acc, r)
            for name, role in sorted(a.get("roles", {}).items()):
                arn = self.role_arn(acc, name)
                self.roles_by_arn[arn] = (acc, name)
        self.member_path = {}
        if self.org:
            self._walk(self.org["root"], [])

    def _walk(self, node, path):
        levels = path + [node.get("scps", [])]
        for acct in node.get("accounts", []):
            self.member_path[acct["id"]] = levels + [acct.get("scps", [])]
        for ch in node.get("children", []):
            self._walk(ch, levels)

    def role_arn(self, acc, name):
        role = self.accounts[acc]["roles"][name]
        path = role.get("path", "/") or "/"
        return f"arn:aws:iam::{acc}:role{path}{name}"

    def managed(self, acc, arn):
        if arn in self.aws_managed:
            return self.aws_managed[arn]
        for a in self.accounts.values():
            if arn in a.get("managed_policies", {}):
                return a["managed_policies"][arn]
        return None

    def scp_doc(self, name):
        return self.org.get("policies", {}).get(name)


def principal_info(snap, p):
    acc = p["account"]
    a = snap.accounts.get(acc, {})
    info = {"account": acc, "type": p["type"], "tags": {}, "ident": [], "boundary": None, "session": None}
    if p["type"] == "user":
        u = a["users"][p["name"]]
        info["arn"] = f"arn:aws:iam::{acc}:user/{p['name']}"
        info["tags"] = dict(u.get("tags", {}))
        docs = list(u.get("policies", [])) + [snap.managed(acc, m) for m in u.get("managed_policies", [])]
        for g in u.get("groups", []):
            grp = a.get("groups", {}).get(g)
            if grp:
                docs += list(grp.get("policies", [])) + [snap.managed(acc, m) for m in grp.get("managed_policies", [])]
        info["ident"] = [d for d in docs if d]
        if u.get("permissions_boundary"):
            info["boundary"] = snap.managed(acc, u["permissions_boundary"]) or {"Statement": []}
        info["username"] = p["name"]
    elif p["type"] == "role_session":
        r = a["roles"][p["role"]]
        info["role_arn"] = snap.role_arn(acc, p["role"])
        info["arn"] = f"arn:aws:sts::{acc}:assumed-role/{p['role']}/{p['session_name']}"
        tags = {k.lower(): v for k, v in r.get("tags", {}).items()}
        tags.update({k.lower(): v for k, v in (p.get("session_tags") or {}).items()})
        info["tags"] = tags
        docs = list(r.get("policies", [])) + [snap.managed(acc, m) for m in r.get("managed_policies", [])]
        info["ident"] = [d for d in docs if d]
        if r.get("permissions_boundary"):
            info["boundary"] = snap.managed(acc, r["permissions_boundary"]) or {"Statement": []}
        if p.get("session_policy") is not None:
            info["session"] = p["session_policy"]
    elif p["type"] == "root":
        info["arn"] = f"arn:aws:iam::{acc}:root"
    else:
        raise ValueError(p["type"])
    return info


def resource_info(snap, arn, pacct):
    if arn in snap.roles_by_arn:
        acc, name = snap.roles_by_arn[arn]
        role = snap.accounts[acc]["roles"][name]
        return acc, role.get("trust_policy"), dict(role.get("tags", {}))
    if arn in snap.resources:
        acc, r = snap.resources[arn]
        return acc, r.get("policy"), dict(r.get("tags", {}))
    parts = split_arn(arn)
    if parts and ACCOUNT_RE.match(parts[4]):
        return parts[4], None, {}
    return pacct, None, {}


def build_context(snap, pi, racct, rtags, qctx):
    """Request context: lower-cased keys; empty strings and empty lists are absent."""
    ctx = {}
    for k, v in (qctx or {}).items():
        kl = k.lower()
        if kl.startswith(("aws:principaltag/", "aws:resourcetag/")) or kl in AUTO_KEYS:
            continue
        ctx[kl] = v
    ctx["aws:principalaccount"] = pi["account"]
    ctx["aws:principalarn"] = pi.get("role_arn", pi["arn"])
    ctx["aws:principaltype"] = {"user": "User", "role_session": "AssumedRole", "root": "Account"}[pi["type"]]
    if pi["type"] == "user":
        ctx["aws:username"] = pi["username"]
    for k, v in pi["tags"].items():          # role tags first, then session tags (see principal_info)
        ctx["aws:principaltag/" + k.lower()] = v
    ctx["aws:resourceaccount"] = racct
    for k, v in rtags.items():
        ctx["aws:resourcetag/" + k.lower()] = v
    if snap.org and (pi["account"] in snap.member_path or pi["account"] == snap.org.get("management_account")):
        ctx["aws:principalorgid"] = snap.org["id"]
    return {k: v for k, v in ctx.items() if v not in ("", [], None)}


AUTO_KEYS = {"aws:principalaccount", "aws:principalarn", "aws:principaltype", "aws:username",
             "aws:resourceaccount", "aws:principalorgid"}


# ---------------------------------------------------------------- matching

def statements(doc):
    if not isinstance(doc, dict):
        return []
    return [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]


def stmt_applies(s, action, resource, ctx, version, attached_resource=False):
    if "Action" in s:
        if not any(isinstance(a, str) and action_match(a, action) for a in as_list(s["Action"])):
            return False
    elif "NotAction" in s:
        if any(isinstance(a, str) and action_match(a, action) for a in as_list(s["NotAction"])):
            return False
    else:
        return False
    if "Resource" in s:
        if not any(isinstance(r, str) and arn_match(r, resource, ctx, version) for r in as_list(s["Resource"])):
            return False
    elif "NotResource" in s:
        if any(isinstance(r, str) and arn_match(r, resource, ctx, version) for r in as_list(s["NotResource"])):
            return False
    elif not attached_resource:
        return False
    return condition_block(s.get("Condition"), ctx, version)


def effect(s):
    return s.get("Effect")


def any_effect(docs, eff, action, resource, ctx):
    for d in docs:
        v = d.get("Version")
        for s in statements(d):
            if effect(s) == eff and stmt_applies(s, action, resource, ctx, v):
                return True
    return False


def principal_entries(pel):
    if pel == "*":
        return ["*"]
    if isinstance(pel, dict):
        return [e for e in as_list(pel.get("AWS")) if isinstance(e, str)]
    return []


def entry_kind(entry, pi, negative=False):
    """How a single Principal entry matches the requester: 'direct', 'role', 'account' or None."""
    if entry == "*":
        return "direct"
    acct = None
    if ACCOUNT_RE.match(entry):
        acct = entry
    else:
        m = re.fullmatch(r"arn:aws:iam::(\d{12}):root", entry)
        if m:
            acct = m.group(1)
    if acct is not None:
        if acct != pi["account"]:
            return None
        return "direct" if pi["type"] == "root" else "account"
    if entry == pi["arn"]:
        return "direct"
    if not negative and pi["type"] == "role_session" and entry == pi["role_arn"]:
        return "role"
    return None


RANK = {"direct": 3, "role": 2, "account": 1}


def rp_match_kind(s, pi):
    if "Principal" in s:
        best = None
        for e in principal_entries(s["Principal"]):
            k = entry_kind(e, pi)
            if k and (best is None or RANK[k] > RANK[best]):
                best = k
        return best
    if "NotPrincipal" in s:
        for e in principal_entries(s["NotPrincipal"]):
            if entry_kind(e, pi, negative=True):
                return None
        return "direct"
    return None


def authorize(snap, p, action, resource, qctx):
    pi = principal_info(snap, p)
    racct, rp, rtags = resource_info(snap, resource, pi["account"])
    ctx = build_context(snap, pi, racct, rtags, qctx)

    scp_levels = []
    if snap.org and pi["account"] in snap.member_path and pi["account"] != snap.org.get("management_account"):
        scp_levels = [[snap.scp_doc(n) or {"Statement": []} for n in lvl] for lvl in snap.member_path[pi["account"]]]

    side_docs = list(pi["ident"])
    if pi["boundary"] is not None:
        side_docs.append(pi["boundary"])
    if pi["session"] is not None:
        side_docs.append(pi["session"])
    for lvl in scp_levels:
        side_docs += lvl
    if any_effect(side_docs, "Deny", action, resource, ctx):
        return "ExplicitDeny"

    rp_kind = None
    if isinstance(rp, dict):
        v = rp.get("Version")
        for s in statements(rp):
            k = rp_match_kind(s, pi)
            if k is None or not stmt_applies(s, action, resource, ctx, v, attached_resource=True):
                continue
            if effect(s) == "Deny":
                return "ExplicitDeny"
            if effect(s) == "Allow" and (rp_kind is None or RANK[k] > RANK[rp_kind]):
                rp_kind = k

    for lvl in scp_levels:
        if not any_effect(lvl, "Allow", action, resource, ctx):
            return "ImplicitDeny"

    is_root = pi["type"] == "root"
    ident_allow = is_root or any_effect(pi["ident"], "Allow", action, resource, ctx)
    boundary_ok = pi["boundary"] is None or any_effect([pi["boundary"]], "Allow", action, resource, ctx)
    session_ok = pi["session"] is None or any_effect([pi["session"]], "Allow", action, resource, ctx)

    if racct == pi["account"]:
        if is_root or rp_kind == "direct":
            return "Allow"
        base = ident_allow or rp_kind == "role"
        return "Allow" if base and boundary_ok and session_ok else "ImplicitDeny"
    ident_side = ident_allow and boundary_ok and session_ok
    return "Allow" if ident_side and rp_kind is not None else "ImplicitDeny"


def all_role_arns(snap):
    return sorted(snap.roles_by_arn)


def reachable_roles(snap, p, qctx):
    session = (p.get("hop_session_name") or "hop")
    seen, order = set(), []
    frontier = [p]
    roles = all_role_arns(snap)
    while frontier:
        nxt = []
        for cur in frontier:
            for arn in roles:
                if arn in seen:
                    continue
                if authorize(snap, cur, "sts:AssumeRole", arn, qctx) == "Allow":
                    seen.add(arn)
                    acc, name = snap.roles_by_arn[arn]
                    nxt.append({"type": "role_session", "account": acc, "role": name, "session_name": session})
        frontier = nxt
    return sorted(seen)


def who_can(snap, action, resource, qctx):
    out = []
    for acc in sorted(snap.accounts):
        a = snap.accounts[acc]
        for u in sorted(a.get("users", {})):
            if authorize(snap, {"type": "user", "account": acc, "name": u}, action, resource, qctx) == "Allow":
                out.append(f"arn:aws:iam::{acc}:user/{u}")
        for r in sorted(a.get("roles", {})):
            pr = {"type": "role_session", "account": acc, "role": r, "session_name": "who"}
            if authorize(snap, pr, action, resource, qctx) == "Allow":
                out.append(snap.role_arn(acc, r))
    return sorted(out)


def answer(snap, q):
    t = q["type"]
    if t == "authorize":
        return {"id": q["id"], "decision": authorize(snap, q["principal"], q["action"], q["resource"], q.get("context"))}
    if t == "reachable_roles":
        p = dict(q["principal"])
        p["hop_session_name"] = q.get("session_name", "hop")
        return {"id": q["id"], "roles": reachable_roles(snap, p, q.get("context"))}
    if t == "who_can":
        return {"id": q["id"], "principals": who_can(snap, q["action"], q["resource"], q.get("context"))}
    raise ValueError(t)


def main():
    snap = Snapshot(json.load(open(sys.argv[1], encoding="utf-8")))
    out = sys.stdout
    with open(sys.argv[2], encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.write(json.dumps(answer(snap, json.loads(line)), sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
