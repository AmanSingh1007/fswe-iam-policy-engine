"""Random account snapshots and query sets for the IAM engine task.

make_scenario(seed) -> (snapshot, queries). Answers come from the reference
engine; this module only shapes inputs so that every rule in SPEC.md is
exercised and the three decisions are all well represented.
"""
import random
import uuid

REGIONS = ["us-east-1", "eu-west-1", "ap-south-1"]
TEAMS = ["red", "blue", "green"]


def acct(r):
    return str(r.randrange(10 ** 11, 10 ** 12)).rjust(12, "0")


class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)
        r = self.r
        self.mgmt, self.a, self.b, self.ext = acct(r), acct(r), acct(r), acct(r)
        self.org_id = "o-" + "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(10))
        self.region = r.choice(REGIONS)
        self.snap = {"accounts": {}, "aws_managed_policies": {}}
        self.queries = []

    # ------------------------------------------------------------ helpers
    def v(self):
        # Most policies use the current language version; some do not (variables stay literal).
        return "2012-10-17" if self.r.random() < 0.85 else self.r.choice(["2008-10-17", None])

    def doc(self, stmts, version="auto"):
        d = {"Statement": stmts if self.r.random() < 0.8 or len(stmts) != 1 else stmts[0]}
        ver = self.v() if version == "auto" else version
        if ver:
            d["Version"] = ver
        return d

    def bucket(self, owner, name):
        return f"arn:aws:s3:::{name}"

    def queue(self, owner, name):
        return f"arn:aws:sqs:{self.region}:{owner}:{name}"

    def key(self, owner, kid):
        return f"arn:aws:kms:{self.region}:{owner}:key/{kid}"

    def table(self, owner, name):
        return f"arn:aws:dynamodb:{self.region}:{owner}:table/{name}"

    def secret(self, owner, name):
        return f"arn:aws:secretsmanager:{self.region}:{owner}:secret:{name}-{self.r.choice(['AbC1x2', 'Zz09Qe', 'p0q9r8'])}"

    # ------------------------------------------------------------ building
    def build(self):
        r = self.r
        self.snap["aws_managed_policies"] = {
            "arn:aws:iam::aws:policy/AdministratorAccess": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            "arn:aws:iam::aws:policy/ReadOnlyAccess": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "sqs:Get*", "dynamodb:GetItem", "dynamodb:Query", "kms:Describe*"], "Resource": "*"}]},
        }
        for acc in (self.mgmt, self.a, self.b, self.ext):
            self.snap["accounts"][acc] = {"users": {}, "groups": {}, "roles": {}, "managed_policies": {}, "resources": []}
        self.make_org()
        for acc in (self.a, self.b, self.ext, self.mgmt):
            self.make_resources(acc)
        for acc in (self.a, self.b, self.ext, self.mgmt):
            self.make_iam(acc)
        for acc in (self.a, self.b, self.ext, self.mgmt):
            self.attach_resource_policies(acc)
        return self.snap

    def make_org(self):
        r = self.r
        pol = {
            "FullAWSAccess": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            "AllowCoreServices": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*", "sqs:*", "sts:*", "kms:*", "iam:Get*"], "Resource": "*"}]},
            "DenyKmsDeletion": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": ["kms:ScheduleKeyDeletion", "kms:Disable*"], "Resource": "*"}]},
            "RegionLock": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "NotAction": ["iam:*", "sts:*"], "Resource": "*",
                                                                  "Condition": {"StringNotEquals": {"aws:RequestedRegion": [self.region]}}}]},
            "DenyUnlessMfaForDeletes": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": ["s3:DeleteObject", "dynamodb:DeleteItem"], "Resource": "*",
                                                                               "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}}]},
        }
        prod_scps = r.choice([["FullAWSAccess"], ["AllowCoreServices"], ["FullAWSAccess", "DenyKmsDeletion"], ["AllowCoreServices", "RegionLock"]])
        if r.random() < 0.06:
            prod_scps = []
        dev_scps = r.choice([["FullAWSAccess"], ["FullAWSAccess", "DenyUnlessMfaForDeletes"], ["FullAWSAccess", "RegionLock"]])
        root_scps = ["FullAWSAccess"] + (["DenyKmsDeletion"] if r.random() < 0.3 else [])
        self.snap["organization"] = {
            "id": self.org_id,
            "management_account": self.mgmt,
            "policies": pol,
            "root": {
                "id": "r-" + uuid.UUID(int=r.getrandbits(128)).hex[:4],
                "scps": root_scps,
                "accounts": [{"id": self.mgmt, "scps": ["FullAWSAccess"] if r.random() < 0.5 else []}],
                "children": [
                    {"id": "ou-prod", "scps": prod_scps, "accounts": [{"id": self.a, "scps": r.choice([["FullAWSAccess"], ["FullAWSAccess", "DenyUnlessMfaForDeletes"], ["AllowCoreServices"]])}], "children": []},
                    {"id": "ou-dev", "scps": dev_scps, "accounts": [{"id": self.b, "scps": ["FullAWSAccess"]}], "children": []},
                ],
            },
        }

    def make_resources(self, acc):
        r = self.r
        res = self.snap["accounts"][acc]["resources"]
        tag = lambda: {"team": r.choice(TEAMS), "env": r.choice(["prod", "dev"])} if r.random() < 0.8 else {}
        bname = f"data-{acc[-4:]}-{r.randrange(1000)}"
        self.snap["accounts"][acc]["_bucket"] = bname
        res.append({"arn": self.bucket(acc, bname), "tags": tag()})
        for k in ["reports/q1.csv", "homes/alice/notes.txt", "homes/bob/notes.txt", "public/index.html", "secret/keys.txt", "a*b/literal.txt"]:
            res.append({"arn": self.bucket(acc, bname) + "/" + k, "tags": tag()})
        res.append({"arn": self.queue(acc, "jobs"), "tags": tag()})
        res.append({"arn": self.key(acc, str(uuid.UUID(int=r.getrandbits(128)))), "tags": tag()})
        res.append({"arn": self.table(acc, "Orders"), "tags": tag()})
        res.append({"arn": self.secret(acc, "db/password"), "tags": tag()})

    def principal_arns(self, acc):
        a = self.snap["accounts"][acc]
        out = [f"arn:aws:iam::{acc}:user/{u}" for u in a["users"]]
        for n, ro in a["roles"].items():
            out.append(f"arn:aws:iam::{acc}:role{ro.get('path', '/')}{n}")
        return out

    def ident_stmt(self, acc):
        r = self.r
        a = self.snap["accounts"][acc]
        bname = a["_bucket"]
        other = self.snap["accounts"][r.choice([self.a, self.b, self.ext])]
        ob = other["_bucket"]
        res = [x["arn"] for x in a["resources"]]
        choices = [
            lambda: {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{r.choice([bname, ob])}/*"},
            lambda: {"Effect": "Allow", "Action": r.choice(["s3:*", "S3:Get*", "s3:?etObject", "s3:List*"]), "Resource": [f"arn:aws:s3:::{bname}", f"arn:aws:s3:::{bname}*"]},
            lambda: {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": f"arn:aws:s3:::{r.choice([bname, ob])}/homes/${{aws:username}}/*"},
            lambda: {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bname}/homes/${{aws:username, 'alice'}}/*"},
            lambda: {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bname}/a${{*}}b/*"},
            lambda: {"Effect": "Allow", "Action": ["sqs:SendMessage", "sqs:ReceiveMessage"], "Resource": f"arn:aws:sqs:*:{r.choice([acc, '*'])}:jobs"},
            lambda: {"Effect": "Allow", "Action": "kms:*", "Resource": "*", "Condition": {"StringEquals": {"aws:ResourceTag/team": "${aws:PrincipalTag/team}"}}},
            lambda: {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:ScheduleKeyDeletion"], "Resource": f"arn:aws:kms:*:{acc}:key/*"},
            lambda: {"Effect": "Allow", "Action": "dynamodb:*", "Resource": f"arn:aws:dynamodb:*:*:table/Orders",
                     "Condition": {r.choice(["ForAllValues:StringEquals", "ForAnyValue:StringEquals", "StringEquals"]): {"dynamodb:Attributes": ["id", "status", "total"]}}},
            lambda: {"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:DeleteItem"], "Resource": r.choice(res)},
            lambda: {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": r.choice([f"arn:aws:secretsmanager:*:{acc}:secret:db/*", f"arn:aws:secretsmanager:{self.region}:{acc}:secret:db/password-??????", f"arn:aws:secretsmanager:{self.region}:{acc}:secret:db/password"])},
            lambda: {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": r.choice([f"arn:aws:iam::{r.choice([self.a, self.b, self.ext])}:role/*", f"arn:aws:iam::{acc}:role/ops*", f"arn:aws:iam::*:role/team/*", "*"])},
            lambda: {"Effect": "Allow", "NotAction": ["iam:*", "kms:*"], "Resource": "*"},
            lambda: {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bname}", "Condition": {"NumericLessThanEquals": {"s3:max-keys": r.choice(["10", 10, "100"])}}},
            lambda: {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": {"DateLessThan": {"aws:CurrentTime": r.choice(["2026-06-30T00:00:00Z", "2027-01-01T00:00:00Z", "1780000000"])}}},
            lambda: {"Effect": "Allow", "Action": "sqs:*", "Resource": "*", "Condition": {"IpAddress": {"aws:SourceIp": r.choice(["10.0.0.0/8", "192.168.1.0/24", "203.0.113.7/32"])}}},
            lambda: {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"StringLike": {"aws:PrincipalArn": r.choice([f"arn:aws:iam::{acc}:role/team/*", f"arn:aws:iam::{acc}:user/a*"])}}},
            lambda: {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"ArnEquals": {"aws:PrincipalArn": f"arn:aws:iam::*:role/team/*"}}},
            # denies
            lambda: {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*", "Condition": {r.choice(["BoolIfExists", "Bool"]): {"aws:MultiFactorAuthPresent": r.choice(["false", False])}}},
            lambda: {"Effect": "Deny", "NotResource": [f"arn:aws:s3:::{bname}", f"arn:aws:s3:::{bname}/*"], "Action": "s3:*"},
            lambda: {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"NotIpAddress": {"aws:SourceIp": ["10.0.0.0/8", "172.16.0.0/12"]}}},
            lambda: {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"StringNotEqualsIfExists": {"aws:RequestedRegion": self.region}}},
            lambda: {"Effect": "Deny", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::*/secret/*", "Condition": {"StringNotEquals": {"aws:PrincipalTag/clearance": "high"}}},
            lambda: {"Effect": "Deny", "Action": "dynamodb:*", "Resource": "*", "Condition": {"ForAnyValue:StringEquals": {"dynamodb:Attributes": ["ssn", "card"]}}},
            lambda: {"Effect": "Deny", "Action": "kms:*", "Resource": "*", "Condition": {"Null": {"aws:ResourceTag/team": r.choice(["true", True])}}},
            lambda: {"Effect": "Deny", "Action": "sqs:*", "Resource": "*", "Condition": {"ForAllValues:StringLike": {"aws:TagKeys": ["temp-*"]}}},
        ]
        return r.choice(choices)()

    def make_iam(self, acc):
        r = self.r
        a = self.snap["accounts"][acc]
        mp = f"arn:aws:iam::{acc}:policy/"
        a["managed_policies"][mp + "S3Boundary"] = self.doc([{"Effect": "Allow", "Action": ["s3:*", "sts:AssumeRole"], "Resource": "*"}], version="2012-10-17")
        a["managed_policies"][mp + "TeamBoundary"] = self.doc([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
                                                                {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}], version="2012-10-17")
        a["managed_policies"][mp + "Shared"] = self.doc([self.ident_stmt(acc) for _ in range(r.randint(1, 3))])
        a["groups"]["devs"] = {"policies": [self.doc([self.ident_stmt(acc) for _ in range(r.randint(1, 2))])],
                               "managed_policies": [r.choice([mp + "Shared", "arn:aws:iam::aws:policy/ReadOnlyAccess"])]}
        a["groups"]["auditors"] = {"policies": [], "managed_policies": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]}
        for name in ["alice", "bob", "carol", "dave"]:
            u = {"tags": {}, "groups": [], "policies": [], "managed_policies": []}
            if r.random() < 0.7:
                u["tags"]["team"] = r.choice(TEAMS)
            if r.random() < 0.3:
                u["tags"]["clearance"] = r.choice(["high", "low"])
            u["groups"] = r.sample(["devs", "auditors", "ghosts"], r.randint(0, 2))
            u["policies"] = [self.doc([self.ident_stmt(acc) for _ in range(r.randint(1, 3))]) for _ in range(r.randint(0, 2))]
            if r.random() < 0.3:
                u["managed_policies"].append(r.choice([mp + "Shared", "arn:aws:iam::aws:policy/AdministratorAccess", mp + "Missing"]))
            if r.random() < 0.35:
                u["permissions_boundary"] = r.choice([mp + "S3Boundary", mp + "TeamBoundary", mp + "NoSuchBoundary"])
            a["users"][name] = u
        role_specs = [("ops-admin", "/"), ("deploy", "/team/"), ("reader", "/"), ("auditor", "/team/"), ("svc-lambda", "/service/")]
        for name, path in role_specs:
            ro = {"path": path, "tags": {}, "policies": [], "managed_policies": []}
            if r.random() < 0.7:
                ro["tags"]["team"] = r.choice(TEAMS)
            ro["policies"] = [self.doc([self.ident_stmt(acc) for _ in range(r.randint(1, 3))])]
            if name == "ops-admin" and r.random() < 0.6:
                ro["managed_policies"].append("arn:aws:iam::aws:policy/AdministratorAccess")
            if r.random() < 0.3:
                ro["permissions_boundary"] = r.choice([mp + "S3Boundary", mp + "TeamBoundary"])
            ro["trust_policy"] = self.trust_policy(acc, name)
            a["roles"][name] = ro

    def trust_policy(self, acc, name):
        r = self.r
        others = [x for x in (self.a, self.b, self.ext, self.mgmt) if x != acc]
        o = r.choice(others)
        role_path_arn = lambda ac, rn, p: f"arn:aws:iam::{ac}:role{p}{rn}"
        opts = [
            lambda: {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{r.choice([acc, o])}:root"}, "Action": "sts:AssumeRole"},
            lambda: {"Effect": "Allow", "Principal": {"AWS": r.choice([acc, o])}, "Action": "sts:AssumeRole",
                     "Condition": {"StringEquals": {"sts:ExternalId": "ext-" + acc[-3:]}}},
            lambda: {"Effect": "Allow", "Principal": {"AWS": [f"arn:aws:iam::{r.choice([acc, o])}:user/{r.choice(['alice', 'bob', 'carol'])}"]}, "Action": "sts:AssumeRole"},
            lambda: {"Effect": "Allow", "Principal": {"AWS": role_path_arn(r.choice([acc, o]), r.choice(["deploy", "ops-admin", "reader"]), r.choice(["/", "/team/"]))}, "Action": "sts:AssumeRole"},
            lambda: {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:sts::{acc}:assumed-role/{r.choice(['deploy', 'reader'])}/{r.choice(['hop', 'ci'])}"}, "Action": "sts:AssumeRole"},
            lambda: {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"},
            lambda: {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:PrincipalOrgID": self.org_id}}},
            lambda: {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}, "StringEquals": {"aws:PrincipalAccount": [acc, o]}}},
            lambda: {"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:PrincipalTag/team": "red"}}},
        ]
        stmts = [r.choice(opts)() for _ in range(r.randint(1, 3))]
        return self.doc(stmts)

    def attach_resource_policies(self, acc):
        r = self.r
        a = self.snap["accounts"][acc]
        others = [x for x in (self.a, self.b, self.ext, self.mgmt) if x != acc]
        o = r.choice(others)
        bname = a["_bucket"]
        ref_principals = self.principal_arns(acc) + self.principal_arns(o)

        def pol(target):
            opts = [
                lambda: {"Effect": "Allow", "Principal": {"AWS": r.choice([f"arn:aws:iam::{o}:root", o, f"arn:aws:iam::{acc}:root"])}, "Action": r.choice(["s3:GetObject", "s3:*", "sqs:SendMessage", "kms:*", "*"]), "Resource": target},
                lambda: {"Effect": "Allow", "Principal": {"AWS": r.choice(ref_principals)}, "Action": "*", "Resource": target},
                lambda: {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:sts::{r.choice([acc, o])}:assumed-role/{r.choice(['deploy', 'reader', 'auditor'])}/{r.choice(['hop', 'who', 'ci', 's1'])}"}, "Action": "*"},
                lambda: {"Effect": "Allow", "Principal": "*", "Action": r.choice(["s3:GetObject", "sqs:SendMessage", "*"]), "Resource": target, "Condition": {"StringEquals": {"aws:PrincipalOrgID": self.org_id}}},
                lambda: {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bname}/public/*"},
                lambda: {"Effect": "Deny", "NotPrincipal": {"AWS": [f"arn:aws:iam::{acc}:role/team/deploy", f"arn:aws:iam::{acc}:user/alice"]}, "Action": "*", "Resource": f"arn:aws:s3:::{bname}/secret/*"},
                lambda: {"Effect": "Deny", "Principal": "*", "Action": "*", "Resource": target, "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
                lambda: {"Effect": "Deny", "Principal": {"AWS": f"arn:aws:iam::{o}:root"}, "Action": r.choice(["s3:DeleteObject", "kms:ScheduleKeyDeletion", "sqs:DeleteQueue"]), "Resource": target},
                lambda: {"Effect": "Allow", "Principal": {"AWS": r.choice(ref_principals)}, "Action": r.choice(["kms:Decrypt", "secretsmanager:GetSecretValue", "dynamodb:GetItem"]),
                         "Condition": {"StringEqualsIgnoreCase": {"aws:PrincipalTag/team": r.choice(["RED", "Blue", "green"])}}},
            ]
            return self.doc([r.choice(opts)() for _ in range(r.randint(1, 4))])

        for res in a["resources"]:
            if r.random() < 0.65:
                res["policy"] = pol(r.choice([res["arn"], "*", res["arn"].split("/")[0] + "/*" if "/" in res["arn"] else res["arn"]]))

    # ------------------------------------------------------------ queries
    def principals(self):
        out = []
        for acc in (self.a, self.b, self.ext, self.mgmt):
            a = self.snap["accounts"][acc]
            for u in a["users"]:
                out.append({"type": "user", "account": acc, "name": u})
            for ro in a["roles"]:
                p = {"type": "role_session", "account": acc, "role": ro, "session_name": self.r.choice(["hop", "ci", "who", "s1"])}
                if self.r.random() < 0.25:
                    p["session_policy"] = self.doc([self.ident_stmt(acc) for _ in range(self.r.randint(1, 2))])
                if self.r.random() < 0.3:
                    p["session_tags"] = {self.r.choice(["team", "Team", "clearance"]): self.r.choice(TEAMS + ["high"])}
                out.append(p)
            if self.r.random() < 0.5:
                out.append({"type": "root", "account": acc})
        return out

    def context(self):
        r = self.r
        c = {}
        if r.random() < 0.8:
            c["aws:SourceIp"] = r.choice(["10.1.2.3", "192.168.1.20", "203.0.113.7", "198.51.100.4", "172.20.0.9"])
        if r.random() < 0.7:
            c["aws:MultiFactorAuthPresent"] = r.choice(["true", "false"])
        if r.random() < 0.7:
            c["aws:SecureTransport"] = r.choice(["true", "true", "false"])
        if r.random() < 0.75:
            c["aws:RequestedRegion"] = r.choice([self.region] * 3 + REGIONS)
        if r.random() < 0.7:
            c["aws:CurrentTime"] = r.choice(["2026-03-01T12:00:00Z", "2026-11-15T08:30:00+05:30", "2027-02-01T00:00:00Z"])
        if r.random() < 0.4:
            c["s3:max-keys"] = r.choice(["5", "10", "50", "abc"])
        if r.random() < 0.5:
            c["dynamodb:Attributes"] = r.choice([["id"], ["id", "status"], ["id", "ssn"], [], ["total", "card"]])
        if r.random() < 0.3:
            c["aws:TagKeys"] = r.choice([["temp-a"], ["temp-a", "owner"], []])
        if r.random() < 0.3:
            c["sts:ExternalId"] = r.choice(["ext-" + x[-3:] for x in (self.a, self.b, self.ext)])
        if r.random() < 0.15:
            c["aws:PrincipalTag/team"] = "red"  # requester-supplied principal tags are ignored
        return c

    def actions_for(self, arn):
        if arn.startswith("arn:aws:s3"):
            return ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "S3:getobject"]
        if ":sqs:" in arn:
            return ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteQueue"]
        if ":kms:" in arn:
            return ["kms:Decrypt", "kms:ScheduleKeyDeletion", "kms:DescribeKey"]
        if ":dynamodb:" in arn:
            return ["dynamodb:GetItem", "dynamodb:DeleteItem", "dynamodb:Query"]
        if ":secretsmanager:" in arn:
            return ["secretsmanager:GetSecretValue"]
        if ":role" in arn:
            return ["sts:AssumeRole", "sts:AssumeRole", "iam:GetRole"]
        return ["s3:GetObject"]

    def resources(self):
        out = []
        for acc in (self.a, self.b, self.ext, self.mgmt):
            a = self.snap["accounts"][acc]
            out += [x["arn"] for x in a["resources"]]
            out += [f"arn:aws:iam::{acc}:role{ro['path']}{n}" for n, ro in a["roles"].items()]
            out.append(f"arn:aws:s3:::{a['_bucket']}/homes/carol/unregistered.txt")
            out.append(f"arn:aws:sqs:{self.region}:{acc}:unregistered-queue")
        return out


def add_fixtures(g):
    """Deterministic corner cases planted in every scenario: an account outside the
    organization (E) and a fifth member account (F) under an OU whose SCP omits DynamoDB.
    Returns the queries that probe them."""
    r, snap = g.r, g.snap
    E = g.ext
    F = acct(r)
    v12 = "2012-10-17"
    a = snap["accounts"][E]
    bucket = f"fx-{E}-{r.randrange(10 ** 4)}"
    B = f"arn:aws:s3:::{bucket}"
    sess_arn = lambda role, s: f"arn:aws:sts::{E}:assumed-role/{role}/{s}"
    role_arn = lambda role, path="/team/": f"arn:aws:iam::{E}:role{path}{role}"
    user_arn = lambda u: f"arn:aws:iam::{E}:user/{u}"
    mp = f"arn:aws:iam::{E}:policy/"
    a["managed_policies"][mp + "FxSqsOnly"] = {"Version": v12, "Statement": [{"Effect": "Allow", "Action": "sqs:*", "Resource": "*"}]}
    kid = str(uuid.UUID(int=r.getrandbits(128)))
    key = f"arn:aws:kms:{g.region}:{E}:key/{kid}"
    objs = {
        "doc": B + "/fx/doc.txt", "secret": B + "/fx/secret.txt", "star": B + "/fx/a*b/x.txt", "nostar": B + "/fx/aZZb/x.txt",
        "home2008": B + "/homes/fx-v2008/a.txt", "home2012": B + "/homes/fx-v2012/a.txt", "shared": B + "/homes/shared/a.txt",
        "literal": B + "/homes/${aws:username}/x.txt", "other": B + "/fx/other.txt",
    }
    res = a["resources"]
    res.append({"arn": objs["doc"], "policy": {"Version": v12, "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": sess_arn("fx-writer", "s1")}, "Action": "s3:GetObject"},
        {"Effect": "Allow", "Principal": {"AWS": role_arn("fx-writer")}, "Action": "s3:PutObject"}]}})
    res.append({"arn": objs["secret"], "policy": {"Version": v12, "Statement": [
        {"Effect": "Deny", "NotPrincipal": {"AWS": [role_arn("fx-writer"), user_arn("fx-alice")]}, "Action": "s3:GetObject"},
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}})
    for k in ("star", "nostar", "home2008", "home2012", "shared", "literal", "other"):
        res.append({"arn": objs[k]})
    res.append({"arn": key, "tags": {"team": "blue"}})
    users = {
        "fx-alice": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}],
        "fx-v2008": None, "fx-v2012": None,
        "fx-star": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": B + "/fx/a${*}b/*"}],
        "fx-arn": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": B + "/fx/*",
                    "Condition": {"ArnEquals": {"aws:PrincipalArn": f"arn:aws:iam::{E}:user/fx-*"}}}],
        "fx-dyn": [{"Effect": "Allow", "Action": "dynamodb:Query", "Resource": "*",
                    "Condition": {"ForAllValues:StringEquals": {"dynamodb:Attributes": ["id", "status"]}}}],
        "fx-noclear": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                       {"Effect": "Deny", "Action": "s3:GetObject", "Resource": B + "/fx/*",
                        "Condition": {"StringNotEquals": {"aws:PrincipalTag/clearance": "high"}}}],
        "fx-nb": [],
    }
    for u, stmts in users.items():
        a["users"][u] = {"tags": {}, "groups": [], "policies": [], "managed_policies": []}
        if stmts:
            a["users"][u]["policies"] = [{"Version": v12, "Statement": stmts}]
    home = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": B + "/homes/${aws:username}/*"}
    a["users"]["fx-v2008"]["policies"] = [{"Version": "2008-10-17", "Statement": [home]}]
    a["users"]["fx-v2012"]["policies"] = [{"Version": v12, "Statement": [home]}]
    a["users"]["fx-nb"]["managed_policies"] = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    a["users"]["fx-nb"]["permissions_boundary"] = mp + "FxNoSuchBoundary"
    roles = {
        "fx-writer": ("/team/", {}, [], mp + "FxSqsOnly", [{"Effect": "Allow", "Principal": {"AWS": E}, "Action": "sts:AssumeRole"}]),
        "fx-home": ("/", {}, [{"Effect": "Allow", "Action": "s3:GetObject",
                               "Resource": [B + "/homes/${aws:username, 'shared'}/*", B + "/homes/${aws:username}/*"]}], None,
                    [{"Effect": "Allow", "Principal": {"AWS": E}, "Action": "sts:AssumeRole"}]),
        "fx-tagged": ("/", {"team": "red"}, [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*",
                                               "Condition": {"StringEquals": {"aws:ResourceTag/team": "${aws:PrincipalTag/team}"}}}], None,
                      [{"Effect": "Allow", "Principal": {"AWS": E}, "Action": "sts:AssumeRole"}]),
        "fx-hop1": ("/team/", {}, [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}], None,
                    [{"Effect": "Allow", "Principal": {"AWS": user_arn("fx-alice")}, "Action": "sts:AssumeRole"}]),
        "fx-hop2": ("/", {}, [], None, [{"Effect": "Allow", "Principal": {"AWS": sess_arn("fx-hop1", "hop")}, "Action": "sts:AssumeRole"}]),
    }
    for name, (path, tags, stmts, boundary, trust) in roles.items():
        ro = {"path": path, "tags": tags, "policies": [{"Version": v12, "Statement": stmts}] if stmts else [],
              "managed_policies": [], "trust_policy": {"Version": v12, "Statement": trust}}
        if boundary:
            ro["permissions_boundary"] = boundary
        a["roles"][name] = ro

    # fifth account F: member of an OU whose only SCP allows core services (no DynamoDB)
    snap["accounts"][F] = {"users": {"fx-dba": {"tags": {}, "groups": [], "policies": [],
                                                "managed_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]}},
                           "groups": {}, "roles": {}, "managed_policies": {},
                           "resources": [{"arn": f"arn:aws:dynamodb:{g.region}:{F}:table/Ledger"}]}
    snap["organization"]["root"]["children"].append(
        {"id": "ou-fx", "scps": ["AllowCoreServices"], "accounts": [{"id": F, "scps": ["FullAWSAccess"]}], "children": []})

    U = lambda n: {"type": "user", "account": E, "name": n}
    S = lambda role, s="s1", **kw: dict({"type": "role_session", "account": E, "role": role, "session_name": s}, **kw)
    ctx = {"aws:SourceIp": "10.1.2.3"}
    qs = [
        (S("fx-writer", "s1"), "s3:GetObject", objs["doc"]),
        (S("fx-writer", "s2"), "s3:GetObject", objs["doc"]),
        (S("fx-writer", "s1"), "s3:PutObject", objs["doc"]),
        (S("fx-writer", "s1"), "s3:GetObject", objs["secret"]),
        (U("fx-alice"), "s3:GetObject", objs["secret"]),
        (U("fx-v2008"), "s3:GetObject", objs["home2008"]),
        (U("fx-v2012"), "s3:GetObject", objs["home2012"]),
        (U("fx-star"), "s3:GetObject", objs["star"]),
        (U("fx-star"), "s3:GetObject", objs["nostar"]),
        (S("fx-home"), "s3:GetObject", objs["shared"]),
        (S("fx-home"), "s3:GetObject", objs["literal"]),
        (S("fx-tagged", session_tags={"team": "blue"}), "kms:Decrypt", key),
        (S("fx-tagged"), "kms:Decrypt", key),
        (U("fx-arn"), "s3:GetObject", objs["other"]),
        (U("fx-dyn"), "dynamodb:Query", f"arn:aws:dynamodb:{g.region}:{E}:table/Orders"),
        (U("fx-noclear"), "s3:GetObject", objs["other"]),
        (U("fx-nb"), "s3:GetObject", objs["other"]),
        ({"type": "user", "account": F, "name": "fx-dba"}, "dynamodb:GetItem", f"arn:aws:dynamodb:{g.region}:{F}:table/Ledger"),
        ({"type": "user", "account": F, "name": "fx-dba"}, "sqs:SendMessage", f"arn:aws:sqs:{g.region}:{F}:jobs"),
    ]
    out = [{"type": "authorize", "principal": p, "action": act, "resource": rs, "context": dict(ctx)} for p, act, rs in qs]
    out.append({"type": "authorize", "principal": U("fx-dyn"), "action": "dynamodb:Query",
                "resource": f"arn:aws:dynamodb:{g.region}:{E}:table/Orders", "context": {"dynamodb:Attributes": ["id", "ssn"]}})
    out.append({"type": "reachable_roles", "principal": U("fx-alice"), "session_name": "hop", "context": dict(ctx)})
    out.append({"type": "reachable_roles", "principal": U("fx-alice"), "session_name": "ci", "context": dict(ctx)})
    return out


def make_scenario(seed, n_auth=300, n_reach=15, n_who=15, engine=None, fixtures=True):
    g = Gen(seed)
    snap = g.build()
    fixture_queries = add_fixtures(g) if fixtures else []
    principals = g.principals()
    resources = g.resources()
    r = g.r
    pool = []
    for i in range(n_auth * 6):
        res = r.choice(resources)
        q = {"type": "authorize", "principal": r.choice(principals), "action": r.choice(g.actions_for(res)), "resource": res, "context": g.context()}
        pool.append(q)
    if engine is not None:
        # stratify by decision so all three outcomes are well represented
        buckets = {"Allow": [], "ExplicitDeny": [], "ImplicitDeny": []}
        es = engine.Snapshot(snap)
        for q in pool:
            buckets[engine.authorize(es, q["principal"], q["action"], q["resource"], q["context"])].append(q)
        want = {"Allow": int(n_auth * 0.4), "ExplicitDeny": int(n_auth * 0.2)}
        want["ImplicitDeny"] = n_auth - want["Allow"] - want["ExplicitDeny"]
        chosen = []
        for k, n in want.items():
            chosen += buckets[k][:n]
        rest = [q for k in buckets for q in buckets[k][want[k]:]]
        chosen += rest[:n_auth - len(chosen)]
        r.shuffle(chosen)
        pool = chosen
    queries = pool[:n_auth]
    for _ in range(n_reach):
        p = dict(r.choice([p for p in principals if p["type"] != "root"] + [p for p in principals if p["type"] == "root"][:1]))
        queries.append({"type": "reachable_roles", "principal": p, "session_name": r.choice(["hop", "ci"]), "context": g.context()})
    for _ in range(n_who):
        res = r.choice(resources)
        queries.append({"type": "who_can", "action": r.choice(g.actions_for(res)), "resource": res, "context": g.context()})
    queries += fixture_queries
    r.shuffle(queries)
    for i, q in enumerate(queries):
        q["id"] = f"q{i:04d}"
    for a in snap["accounts"].values():
        a.pop("_bucket", None)
    return snap, queries
