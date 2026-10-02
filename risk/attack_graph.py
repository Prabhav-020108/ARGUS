"""
ARGUS Phase 2 (P1) - derived attack graph builder.

Turns the Cartography graph in Neo4j into a "hacker-movement" graph.
Every edge means: an attacker who controls the tail can plausibly reach the
head, with probability p (0 < p <= 1) and a type label (etype).

Frozen contract (do not rename):
    build_attack_graph(session) -> nx.DiGraph
    resolve_entry_nodes(G, cfg=None) -> list[node_id]
    get_crown_jewels(G, cfg=None) -> list[node_id]

Rules this module follows:
  * Read-only Cypher only (matching and returning, never changing data).
  * Every probability comes from risk/edge_weights.json and
    risk/privesc_actions.json. Nothing about weights lives in this file.
  * No account ids, ARNs or scenario suffixes in code. Names live in
    risk/config.json.
  * Node id = Cartography arn/id (never Neo4j's internal element id).

Run a live check from the repo root (PowerShell):
    python -m risk.attack_graph
"""

import json
import logging
import os
import re
from collections import Counter
from pathlib import Path

import networkx as nx

from risk.graph_loader import run

log = logging.getLogger(__name__)

_DIR = Path(__file__).resolve().parent
INTERNET = "INTERNET"
ADMIN = "ADMIN_EQUIV"

# Entry names in config.json may match a node's label only for these kinds.
_LABEL_MATCH_KINDS = ("internet", "user", "role", "key")

# ICMP rules expose no service port, so they add no network edge.
_ICMP_PROTOCOLS = ("icmp", "icmpv6", "1", "58")

# ----------------------------------------------------------------------------
# Cypher (all read-only). Kept as module constants so tests can feed rows
# keyed by the exact query text.
# ----------------------------------------------------------------------------

Q_PRINCIPALS = """
MATCH (p:AWSPrincipal)
WHERE p:AWSUser OR p:AWSRole
RETURN coalesce(p.arn, p.id) AS id, p.name AS name, labels(p) AS labels
"""

Q_KEYS = """
MATCH (u:AWSUser)-[:AWS_ACCESS_KEY]->(k:AWSAccountAccessKey)
RETURN coalesce(u.arn, u.id) AS uid, k.accesskeyid AS kid, k.status AS status
"""

# Cartography arrow: role trusts principal.  Attacker movement is the reverse.
Q_TRUST = """
MATCH (role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(p:AWSPrincipal)
WHERE NOT p:AWSServicePrincipal AND NOT p:AWSRootPrincipal
RETURN coalesce(role.arn, role.id) AS rid, coalesce(p.arn, p.id) AS pid
"""

Q_BUCKETS = """
MATCH (b:AWSS3Bucket)
RETURN coalesce(b.arn, 'arn:aws:s3:::' + b.name) AS id, b.name AS name,
       properties(b) AS props
"""

# Optional: tags stored as separate tag nodes (depends on Cartography version).
# Returns zero rows when that structure does not exist, which is fine.
Q_BUCKET_TAGS = """
MATCH (b:AWSS3Bucket)-[:TAGGED]->(t:AWSTag)
RETURN coalesce(b.arn, 'arn:aws:s3:::' + b.name) AS id, t.key AS k, t.value AS v
"""

Q_STATEMENTS = """
MATCH (p:AWSPrincipal)-[:POLICY]->(pol:AWSPolicy)-[:STATEMENT]->(s:AWSPolicyStatement)
WHERE p:AWSUser OR p:AWSRole
RETURN coalesce(p.arn, p.id) AS pid, coalesce(pol.arn, pol.id) AS polid,
       pol.name AS polname, s.id AS stmt_id, s.sid AS stmt_sid,
       s.effect AS effect, s.action AS action, s.resource AS resource
"""

# Inbound rules only. Egress rules also link to a security group and the default
# egress is 0.0.0.0/0 on every group, so they must never be matched here.
Q_NET = """
MATCH (rg:AWSIpRange)-[:MEMBER_OF_IP_RULE]->(rule:AWSIpPermissionInbound)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:AWSEC2SecurityGroup)
WHERE rg.range IN ['0.0.0.0/0', '::/0']
RETURN coalesce(rg.id, rg.range) AS rgid, rg.range AS rgrange,
       coalesce(rule.id, rule.ruleid) AS ruleid,
       rule.fromport AS fp, rule.toport AS tp, rule.protocol AS proto,
       coalesce(sg.id, sg.groupid) AS sgid, sg.name AS sgname
"""

Q_SG_VPC = """
MATCH (sg:AWSEC2SecurityGroup)-[:MEMBER_OF_AWS_VPC]->(v:AWSVpc)
RETURN coalesce(sg.id, sg.groupid) AS sgid, coalesce(v.id, v.vpcid) AS vpcid
"""

ALL_QUERIES = (
    Q_PRINCIPALS, Q_KEYS, Q_TRUST, Q_BUCKETS, Q_BUCKET_TAGS,
    Q_STATEMENTS, Q_NET, Q_SG_VPC,
)

# ----------------------------------------------------------------------------
# Config loading and validation
# ----------------------------------------------------------------------------

REQUIRED_WEIGHT_KEYS = (
    "internet_to_range", "range_to_rule", "net_all_ports", "net_sensitive_port",
    "net_web_port", "sensitive_ports", "sg_to_vpc", "uses_key_active",
    "can_assume", "has_policy", "has_statement", "direct_admin",
    "s3_read", "s3_write",
)


def _load_json(name):
    # utf-8-sig tolerates the BOM that Windows PowerShell can add to files.
    return json.loads((_DIR / name).read_text(encoding="utf-8-sig"))


def _check_probability(name, value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("{} must be a number, got {!r}".format(name, value))
    if not (0 < float(value) <= 1):
        raise ValueError("{} must satisfy 0 < p <= 1, got {!r}".format(name, value))


def _check_weights(W):
    """Fail loudly (and clearly) if edge_weights.json is missing a key."""
    missing = [k for k in REQUIRED_WEIGHT_KEYS if k not in W]
    if missing:
        raise ValueError(
            "risk/edge_weights.json is missing keys: {}".format(", ".join(missing))
        )
    for k in REQUIRED_WEIGHT_KEYS:
        if k != "sensitive_ports":
            _check_probability(k, W[k])
    if not isinstance(W["sensitive_ports"], list):
        raise ValueError("sensitive_ports must be a list of port numbers")


def _check_privesc(PRIV):
    if not isinstance(PRIV, dict) or not PRIV:
        raise ValueError("risk/privesc_actions.json must contain a non-empty 'actions' object")
    for action, p in PRIV.items():
        _check_probability("privesc action {}".format(action), p)


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------

def _as_list(x):
    if x is None:
        return []
    return list(x) if isinstance(x, (list, tuple)) else [x]


def _iam_match(pattern, value):
    """IAM-style wildcard match: '*' = any characters, '?' = one character.
    Case-insensitive. Uses a regex, never startswith."""
    rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(rx, value, re.IGNORECASE) is not None


def _to_port(x, default):
    if x is None:
        return default
    try:
        n = int(x)
    except (TypeError, ValueError):
        return default
    return default if n == -1 else n


def _port_p(fp, tp, proto, W):
    """Probability for an inbound world-open rule, or None if the rule exposes
    no service port (ICMP)."""
    proto_s = str(proto).strip().lower()
    if proto_s in _ICMP_PROTOCOLS:
        return None
    lo = _to_port(fp, 0)
    hi = _to_port(tp, 65535)
    if proto_s == "-1" or (lo == 0 and hi == 65535):
        return W["net_all_ports"]
    if any(lo <= s <= hi for s in W["sensitive_ports"]):
        return W["net_sensitive_port"]
    return W["net_web_port"]


def _res_scope_ok(resources):
    """Simplification: an escalation action counts if it is scoped to '*' or to
    an IAM object (policy, role, user)."""
    return any(
        r == "*" or ":policy/" in r or ":role/" in r or ":user/" in r
        for r in resources
    )


def _best_privesc(acts, PRIV):
    best = 0.0
    for action, p in PRIV.items():
        if any(_iam_match(pat, action) for pat in acts):
            best = max(best, float(p))
    return best


def _bucket_in_scope(resources, bucket_arn):
    for x in resources:
        if x == "*" or _iam_match(x, bucket_arn) or _iam_match(x, bucket_arn + "/x"):
            return True
    return False


def _statement_targets(acts, res, bucket_ids, W, PRIV):
    """What an Allow statement lets an attacker reach.
    Returns a list of (target_node, p, etype)."""
    targets = []
    if "*" in acts and "*" in res:
        targets.append((ADMIN, W["direct_admin"], "DIRECT_ADMIN"))
    elif _res_scope_ok(res):
        best = _best_privesc(acts, PRIV)
        if best > 0:
            targets.append((ADMIN, best, "CAN_ESCALATE"))

    read = any(_iam_match(pat, "s3:GetObject") for pat in acts)
    write = any(_iam_match(pat, "s3:PutObject") for pat in acts)
    if read or write:
        p_access = W["s3_read"] if read else W["s3_write"]
        for arn in bucket_ids:
            if _bucket_in_scope(res, arn):
                targets.append((arn, p_access, "CAN_ACCESS"))
    return targets


class _Builder:
    def __init__(self):
        self.G = nx.DiGraph()
        self.skipped = Counter()

    def node(self, nid, kind, label=None, **attrs):
        if nid is None:
            return
        if nid not in self.G:
            shown = nid if label is None else label
            self.G.add_node(nid, kind=kind, label=str(shown), **attrs)

    def edge(self, u, v, p, etype):
        """Add an edge only if both ends already exist. Duplicates keep max p."""
        if u is None or v is None or p is None or u == v:
            return
        p = float(p)
        if p <= 0:
            return
        if u not in self.G or v not in self.G:
            self.skipped[etype] += 1
            return
        p = min(p, 1.0)
        if self.G.has_edge(u, v):
            if p > self.G[u][v]["p"]:
                self.G[u][v].update(p=p, etype=etype)
        else:
            self.G.add_edge(u, v, p=p, etype=etype)


def _validate(G):
    for n, d in G.nodes(data=True):
        if not d.get("kind") or not isinstance(d.get("label"), str):
            raise ValueError("node {!r} is missing kind/label".format(n))
    for u, v, d in G.edges(data=True):
        _check_probability("edge {} -> {}".format(u, v), d.get("p"))
        if not isinstance(d.get("etype"), str):
            raise ValueError("edge {} -> {} is missing etype".format(u, v))


def summarize(G):
    """Counts used in reports: nodes per kind, edges per etype."""
    return {
        "nodes_by_kind": Counter(d["kind"] for _, d in G.nodes(data=True)),
        "edges_by_etype": Counter(d["etype"] for _, _, d in G.edges(data=True)),
    }


# ----------------------------------------------------------------------------
# The builder
# ----------------------------------------------------------------------------

def _build(session, W, PRIV, cfg):
    _check_weights(W)
    _check_privesc(PRIV)
    b = _Builder()
    b.node(INTERNET, "internet", label="INTERNET")
    b.node(ADMIN, "admin", label="ADMIN_EQUIV")

    # 1. principals (users and roles). Duplicate rows collapse to one node.
    for r in run(session, Q_PRINCIPALS):
        kind = "user" if "AWSUser" in (r.get("labels") or []) else "role"
        b.node(r.get("id"), kind, label=r.get("name"))

    # 2. active access keys -> owning user. Inactive keys add nothing.
    for r in run(session, Q_KEYS):
        kid = r.get("kid")
        if kid is None or str(r.get("status")).lower() != "active":
            continue
        key_node = "KEY:" + str(kid)
        b.node(key_node, "key", label=str(kid))
        b.edge(key_node, r.get("uid"), W["uses_key_active"], "USES_KEY")

    # 3. trust, reversed: the role trusts a principal, so the attacker moves
    #    principal -> role. Principals that are not users/roles in this account
    #    have no node, so those edges are skipped.
    for r in run(session, Q_TRUST):
        b.edge(r.get("pid"), r.get("rid"), W["can_assume"], "CAN_ASSUME")

    # 4. buckets, flagged when tagged as holding personal data
    tag_key = cfg.get("crown_jewel_tag", "contains_personal_data")
    tagged = {}
    for r in run(session, Q_BUCKET_TAGS):
        if str(r.get("k")) == tag_key and str(r.get("v")).lower() == "true":
            tagged[r.get("id")] = True
    bucket_ids = []
    for r in run(session, Q_BUCKETS):
        bid = r.get("id")
        if bid is None:
            continue
        props = r.get("props") or {}
        flag = str(props.get(tag_key, "")).lower() == "true" or bid in tagged
        b.node(bid, "bucket", label=r.get("name"), personal_data=flag)
        if bid not in bucket_ids:
            bucket_ids.append(bid)

    # 5. policies and statements. Only Allow statements; Deny is ignored (a
    #    documented limitation). NotAction statements have no Action and so
    #    add nothing.
    for r in run(session, Q_STATEMENTS):
        if str(r.get("effect")).lower() != "allow":
            continue
        acts = [str(a) for a in _as_list(r.get("action"))]
        res = [str(x) for x in _as_list(r.get("resource"))]
        targets = _statement_targets(acts, res, bucket_ids, W, PRIV)
        pid, polid, stmt_id = r.get("pid"), r.get("polid"), r.get("stmt_id")
        if not targets or pid not in b.G or polid is None or stmt_id is None:
            continue
        b.node(polid, "policy", label=r.get("polname"))
        b.node(stmt_id, "stmt", label=r.get("stmt_sid") or stmt_id)
        b.edge(pid, polid, W["has_policy"], "HAS_POLICY")
        b.edge(polid, stmt_id, W["has_statement"], "HAS_STATEMENT")
        for target, p, etype in targets:
            b.edge(stmt_id, target, p, etype)

    # 6. network exposure from the open internet (inbound rules only)
    for r in run(session, Q_NET):
        p_rule = _port_p(r.get("fp"), r.get("tp"), r.get("proto"), W)
        if p_rule is None:
            b.skipped["ICMP_RULE_IGNORED"] += 1
            continue
        rgid, ruleid, sgid = r.get("rgid"), r.get("ruleid"), r.get("sgid")
        if rgid is None or ruleid is None or sgid is None:
            continue
        b.node(rgid, "iprange", label=r.get("rgrange") or rgid)
        b.node(ruleid, "iprule", label=ruleid)
        b.node(sgid, "sg", label=r.get("sgname") or sgid)
        b.edge(INTERNET, rgid, W["internet_to_range"], "INTERNET_TO_RANGE")
        b.edge(rgid, ruleid, W["range_to_rule"], "RANGE_TO_RULE")
        b.edge(ruleid, sgid, p_rule, "RULE_TO_SG")

    # 7. weak edge from an exposed security group to its VPC
    for r in run(session, Q_SG_VPC):
        sgid, vpcid = r.get("sgid"), r.get("vpcid")
        if vpcid is None or sgid not in b.G or b.G.nodes[sgid]["kind"] != "sg":
            continue
        b.node(vpcid, "vpc", label=vpcid)
        b.edge(sgid, vpcid, W["sg_to_vpc"], "SG_TO_VPC")

    _validate(b.G)
    counts = summarize(b.G)
    log.info("attack graph: %d nodes, %d edges", b.G.number_of_nodes(), b.G.number_of_edges())
    log.info("nodes by kind: %s", dict(counts["nodes_by_kind"]))
    log.info("edges by etype: %s", dict(counts["edges_by_etype"]))
    if b.skipped:
        log.info("skipped (missing endpoint or ignored): %s", dict(b.skipped))
    return b.G


def build_attack_graph(session):
    """Frozen signature. Reads weights and config from risk/*.json."""
    return _build(
        session,
        _load_json("edge_weights.json"),
        _load_json("privesc_actions.json")["actions"],
        _load_json("config.json"),
    )


def resolve_entry_nodes(G, cfg=None):
    """Nodes where attacker access starts. Explicit list from config.json.
    A listed user with active keys is seeded through those keys, otherwise the
    user itself. Excluded principals (the scanner) and their keys never appear."""
    if cfg is None:
        cfg = _load_json("config.json")
    excluded = frozenset(cfg.get("excluded_principals", []))

    blocked = {}
    for n, d in G.nodes(data=True):
        if n in excluded or d.get("label") in excluded:
            blocked[n] = True
            if d.get("kind") == "user":
                for k in G.predecessors(n):
                    if G.nodes[k].get("kind") == "key":
                        blocked[k] = True

    out = {}
    for name in cfg.get("entry_nodes", []):
        hits = [
            n for n, d in G.nodes(data=True)
            if n == name or (d.get("kind") in _LABEL_MATCH_KINDS and d.get("label") == name)
        ]
        for n in hits:
            if n in blocked:
                continue
            if G.nodes[n].get("kind") == "user":
                keys = [k for k in G.predecessors(n) if G.nodes[k].get("kind") == "key"]
                for e in (keys or [n]):
                    out[e] = True
            else:
                out[n] = True
    return sorted(out)


def get_crown_jewels(G, cfg=None):
    """ADMIN_EQUIV plus every bucket flagged personal_data or listed manually
    (by node id or by label) in config.json crown_jewel_ids."""
    if cfg is None:
        cfg = _load_json("config.json")
    manual = frozenset(cfg.get("crown_jewel_ids", []))
    out = {ADMIN: True}
    for n, d in G.nodes(data=True):
        if d.get("kind") == "bucket" and (
            d.get("personal_data") or n in manual or d.get("label") in manual
        ):
            out[n] = True
    return sorted(out)


# ----------------------------------------------------------------------------
# Live check:  python -m risk.attack_graph
# ----------------------------------------------------------------------------

def _load_dotenv_if_needed():
    """If NEO4J_PASSWORD is not in the environment, read it from the repo .env."""
    if os.environ.get("NEO4J_PASSWORD"):
        return
    env_path = _DIR.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _show(G, n):
    d = G.nodes[n]
    if d["kind"] == "key":
        return "key(****{})".format(d["label"][-4:])
    return "{}:{}".format(d["kind"], d["label"])


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    _load_dotenv_if_needed()
    if not os.environ.get("NEO4J_PASSWORD"):
        raise SystemExit(
            "NEO4J_PASSWORD is not defined. Copy .env.example to .env, "
            "or run:  $env:NEO4J_PASSWORD = '<your password>'"
        )
    from risk.graph_loader import get_driver

    driver = get_driver()
    try:
        with driver.session() as session:
            G = build_attack_graph(session)
    finally:
        driver.close()

    cfg = _load_json("config.json")
    counts = summarize(G)
    print()
    print("=== ATTACK GRAPH REPORT ===")
    print("nodes:", G.number_of_nodes(), " edges:", G.number_of_edges())
    print("nodes by kind:", dict(counts["nodes_by_kind"]))
    print("edges by etype:")
    for etype, c in sorted(counts["edges_by_etype"].items()):
        print("   {:20} {}".format(etype, c))
    if counts["edges_by_etype"].get("CAN_ESCALATE", 0) == 0:
        print("!!! WARNING: zero CAN_ESCALATE edges. Expected at least one on the "
              "CloudGoat account. Check the statement action shape in "
              "docs/phase2_verified_facts.md before touching any weights.")

    entries = resolve_entry_nodes(G, cfg)
    jewels = get_crown_jewels(G, cfg)
    print("entry nodes:", [_show(G, n) for n in entries])
    print("crown jewels:", [_show(G, n) for n in jewels])

    print("--- hop paths from each entry to each crown jewel (fewest hops) ---")
    for e in entries:
        for j in jewels:
            if nx.has_path(G, e, j):
                path = nx.shortest_path(G, e, j)
                print("{} -> {}: {} hops".format(_show(G, e), _show(G, j), len(path) - 1))
                print("    " + "  >  ".join(_show(G, x) for x in path))

    print("--- control: excluded principals must NOT reach ADMIN_EQUIV ---")
    for n, d in G.nodes(data=True):
        if d["label"] in cfg.get("excluded_principals", []):
            print("{} reaches ADMIN_EQUIV: {}".format(_show(G, n), nx.has_path(G, n, ADMIN)))


if __name__ == "__main__":
    main()