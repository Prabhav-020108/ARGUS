"""
Tests for risk/attack_graph.py using a FAKE Neo4j session (no database needed).

Fixture rows are shaped like the real Cartography query output. All account
ids, key ids and names below are FAKE. Compare the shapes with
docs/phase2_verified_facts.md and adjust a row here if the real shape differs.

Run from the repo root:
    python -m pytest risk/tests/test_attack_graph.py -v
"""

import copy
import re
import sys
from collections import Counter
from pathlib import Path

import networkx as nx
import pytest

# Make "import risk" work no matter how pytest is launched.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from risk import attack_graph as ag  # noqa: E402
from risk.attack_graph import (  # noqa: E402
    ADMIN,
    INTERNET,
    _build,
    _check_privesc,
    _check_weights,
    _iam_match,
    _port_p,
    _statement_targets,
    get_crown_jewels,
    resolve_entry_nodes,
)

# ----------------------------------------------------------------------------
# Test-only configuration (inline, so tests do not break when real weights move)
# ----------------------------------------------------------------------------

TEST_W = {
    "internet_to_range": 1.0,
    "range_to_rule": 1.0,
    "net_all_ports": 0.95,
    "net_sensitive_port": 0.9,
    "net_web_port": 0.4,
    "sensitive_ports": [22, 3389, 3306, 5432, 1433, 27017, 6379],
    "sg_to_vpc": 0.2,
    "uses_key_active": 0.9,
    "can_assume": 0.6,
    "has_policy": 1.0,
    "has_statement": 1.0,
    "direct_admin": 1.0,
    "s3_read": 0.8,
    "s3_write": 0.7,
}

TEST_PRIV = {
    "iam:CreatePolicyVersion": 0.85,
    "iam:SetDefaultPolicyVersion": 0.85,
    "iam:AttachUserPolicy": 0.9,
    "iam:CreateAccessKey": 0.7,
    "iam:PassRole": 0.4,
}

SCANNER_NAME = "argus-cartography-scanner"
RAYNOR_NAME = "raynor-cgidfake0000000"

TEST_CFG = {
    "entry_nodes": ["INTERNET", RAYNOR_NAME, "argus-test-user"],
    "excluded_principals": [SCANNER_NAME],
    "crown_jewel_ids": [],
    "crown_jewel_tag": "contains_personal_data",
}

# ----------------------------------------------------------------------------
# Fake ids and rows
# ----------------------------------------------------------------------------

ACC = "111122223333"
USER_RAYNOR = "arn:aws:iam::{}:user/{}".format(ACC, RAYNOR_NAME)
USER_TEST = "arn:aws:iam::{}:user/argus-test-user".format(ACC)
USER_SCAN = "arn:aws:iam::{}:user/{}".format(ACC, SCANNER_NAME)
ROLE_A = "arn:aws:iam::{}:role/argus-test-role-a".format(ACC)
ROLE_B = "arn:aws:iam::{}:role/argus-test-role-b".format(ACC)
STRANGER = "arn:aws:iam::999988887777:user/stranger"

BUCKET_NEAR = "arn:aws:s3:::argus-test-pii-near-fake1234"
BUCKET_FAR = "arn:aws:s3:::argus-test-pii-far-fake1234"

POL_RAYNOR = "arn:aws:iam::{}:policy/cg-raynor-policy-cgidfake0000000".format(ACC)
POL_DENY = "arn:aws:iam::{}:policy/deny-everything".format(ACC)
POL_SCAN = "arn:aws:iam::aws:policy/SecurityAudit"
POL_NEAR = "arn:aws:iam::{}:policy/argus-test-read-near".format(ACC)
POL_FAR = "arn:aws:iam::{}:policy/argus-test-read-far".format(ACC)

STMT_RAYNOR = POL_RAYNOR + "/statement/0"
STMT_DENY = POL_DENY + "/statement/0"
STMT_SCAN = POL_SCAN + "/statement/0"
STMT_NEAR = POL_NEAR + "/statement/0"
STMT_FAR = POL_FAR + "/statement/0"

KEY_RAYNOR = "AKIAFAKEFAKEFAKE0001"
KEY_RAYNOR_OLD = "AKIAFAKEFAKEFAKE0002"
KEY_SCAN = "AKIAFAKEFAKEFAKE0003"

RANGE_V4 = "0.0.0.0/0"


def _rows():
    return {
        ag.Q_PRINCIPALS: [
            {"id": USER_RAYNOR, "name": RAYNOR_NAME, "labels": ["AWSUser", "AWSPrincipal"]},
            # duplicate row (same node returned twice) must not double count
            {"id": USER_RAYNOR, "name": RAYNOR_NAME, "labels": ["AWSUser", "AWSPrincipal", "UserAccount"]},
            {"id": USER_TEST, "name": "argus-test-user", "labels": ["AWSUser", "AWSPrincipal"]},
            {"id": USER_SCAN, "name": SCANNER_NAME, "labels": ["AWSUser", "AWSPrincipal"]},
            {"id": ROLE_A, "name": "argus-test-role-a", "labels": ["AWSRole", "AWSPrincipal"]},
            {"id": ROLE_B, "name": "argus-test-role-b", "labels": ["AWSRole", "AWSPrincipal"]},
        ],
        ag.Q_KEYS: [
            {"uid": USER_RAYNOR, "kid": KEY_RAYNOR, "status": "Active"},
            {"uid": USER_RAYNOR, "kid": KEY_RAYNOR_OLD, "status": "Inactive"},
            {"uid": USER_SCAN, "kid": KEY_SCAN, "status": "Active"},
        ],
        ag.Q_TRUST: [
            {"rid": ROLE_A, "pid": USER_TEST},
            {"rid": ROLE_B, "pid": ROLE_A},
            {"rid": ROLE_A, "pid": STRANGER},  # not a principal in this account
        ],
        ag.Q_BUCKETS: [
            {"id": BUCKET_NEAR, "name": "argus-test-pii-near-fake1234",
             "props": {"name": "argus-test-pii-near-fake1234", "contains_personal_data": "true"}},
            {"id": BUCKET_FAR, "name": "argus-test-pii-far-fake1234",
             "props": {"name": "argus-test-pii-far-fake1234"}},
        ],
        ag.Q_BUCKET_TAGS: [
            {"id": BUCKET_FAR, "k": "contains_personal_data", "v": "true"},
            {"id": BUCKET_NEAR, "k": "env", "v": "test"},
        ],
        ag.Q_STATEMENTS: [
            # Raynor-shaped: iam:SetDefaultPolicyVersion hidden among Get*/List*
            {"pid": USER_RAYNOR, "polid": POL_RAYNOR, "polname": "cg-raynor-policy-cgidfake0000000",
             "stmt_id": STMT_RAYNOR, "stmt_sid": None, "effect": "Allow",
             "action": ["iam:Get*", "iam:List*", "iam:SetDefaultPolicyVersion"],
             "resource": ["*"]},
            # Deny must create nothing
            {"pid": USER_TEST, "polid": POL_DENY, "polname": "deny-everything",
             "stmt_id": STMT_DENY, "stmt_sid": None, "effect": "Deny",
             "action": ["iam:*"], "resource": ["*"]},
            # Scanner-like read-only audit policy: no escalation, no object access
            {"pid": USER_SCAN, "polid": POL_SCAN, "polname": "SecurityAudit",
             "stmt_id": STMT_SCAN, "stmt_sid": None, "effect": "Allow",
             "action": ["iam:Get*", "iam:List*", "s3:GetBucketAcl"], "resource": ["*"]},
            # near path
            {"pid": ROLE_A, "polid": POL_NEAR, "polname": "argus-test-read-near",
             "stmt_id": STMT_NEAR, "stmt_sid": None, "effect": "Allow",
             "action": ["s3:GetObject", "s3:ListBucket"],
             "resource": [BUCKET_NEAR, BUCKET_NEAR + "/*"]},
            # far path (action given as a plain string on purpose)
            {"pid": ROLE_B, "polid": POL_FAR, "polname": "argus-test-read-far",
             "stmt_id": STMT_FAR, "stmt_sid": None, "effect": "Allow",
             "action": "s3:GetObject",
             "resource": [BUCKET_FAR, BUCKET_FAR + "/*"]},
        ],
        ag.Q_NET: [
            {"rgid": RANGE_V4, "rgrange": RANGE_V4, "ruleid": "sg-111/in/tcp/22",
             "fp": 22, "tp": 22, "proto": "tcp", "sgid": "sg-111", "sgname": "open-ssh"},
            {"rgid": RANGE_V4, "rgrange": RANGE_V4, "ruleid": "sg-222/in/all",
             "fp": None, "tp": None, "proto": "-1", "sgid": "sg-222", "sgname": "open-all"},
            {"rgid": RANGE_V4, "rgrange": RANGE_V4, "ruleid": "sg-333/in/tcp/80",
             "fp": 80, "tp": 80, "proto": "tcp", "sgid": "sg-333", "sgname": "open-web"},
            {"rgid": RANGE_V4, "rgrange": RANGE_V4, "ruleid": "sg-444/in/icmp",
             "fp": -1, "tp": -1, "proto": "icmp", "sgid": "sg-444", "sgname": "ping-only"},
        ],
        ag.Q_SG_VPC: [
            {"sgid": "sg-111", "vpcid": "vpc-aaa"},
            {"sgid": "sg-999", "vpcid": "vpc-aaa"},  # sg not exposed -> skipped
        ],
    }


class _FakeRecord:
    def __init__(self, row):
        self._row = row

    def data(self):
        return dict(self._row)


class FakeSession:
    """Mimics session.run(cypher, **kw); rows are looked up by exact query text."""

    def __init__(self, rows):
        self.rows = rows
        self.seen = []

    def run(self, cypher, **kw):
        self.seen.append(cypher)
        return [_FakeRecord(r) for r in self.rows.get(cypher, [])]


def _graph(rows=None, cfg=None):
    session = FakeSession(rows if rows is not None else _rows())
    return _build(session, TEST_W, TEST_PRIV, cfg or TEST_CFG)


@pytest.fixture(scope="module")
def G():
    return _graph()


# ----------------------------------------------------------------------------
# Wildcard matching
# ----------------------------------------------------------------------------

def test_wildcard_matching():
    assert _iam_match("iam:*", "iam:SetDefaultPolicyVersion")
    assert not _iam_match("iam:Get*", "iam:SetDefaultPolicyVersion")
    assert _iam_match("iam:Set?efaultPolicyVersion", "iam:SetDefaultPolicyVersion")
    assert _iam_match("IAM:setdefaultpolicyversion", "iam:SetDefaultPolicyVersion")
    assert _iam_match("*", "s3:GetObject")
    assert not _iam_match("iam:Get", "iam:GetUser")           # no accidental prefix match
    assert not _iam_match("iam.*", "iamx:Foo")                # '.' is literal, not a regex dot


# ----------------------------------------------------------------------------
# Direction, filters, shapes
# ----------------------------------------------------------------------------

def test_trust_edge_is_reversed(G):
    assert G.has_edge(USER_TEST, ROLE_A)
    assert not G.has_edge(ROLE_A, USER_TEST)
    assert G[USER_TEST][ROLE_A]["etype"] == "CAN_ASSUME"
    assert G[USER_TEST][ROLE_A]["p"] == TEST_W["can_assume"]
    assert G.has_edge(ROLE_A, ROLE_B)                         # role B trusts role A
    assert not G.has_edge(ROLE_B, ROLE_A)


def test_foreign_principal_is_skipped_without_creating_a_node(G):
    assert STRANGER not in G


def test_inactive_key_creates_nothing(G):
    assert "KEY:" + KEY_RAYNOR_OLD not in G
    assert G.has_edge("KEY:" + KEY_RAYNOR, USER_RAYNOR)
    assert G["KEY:" + KEY_RAYNOR][USER_RAYNOR]["etype"] == "USES_KEY"


def test_deny_statement_creates_no_edges(G):
    assert POL_DENY not in G and STMT_DENY not in G
    assert not nx.has_path(G, USER_TEST, ADMIN)


def test_duplicate_principal_rows_do_not_double_count(G):
    assert [n for n, d in G.nodes(data=True) if d["label"] == RAYNOR_NAME] == [USER_RAYNOR]
    assert Counter(d["kind"] for _, d in G.nodes(data=True))["user"] == 3


def test_every_node_has_kind_and_label(G):
    for n, d in G.nodes(data=True):
        assert d.get("kind"), n
        assert isinstance(d.get("label"), str), n


def test_every_edge_has_valid_p_and_etype(G):
    assert G.number_of_edges() > 0
    for u, v, d in G.edges(data=True):
        assert 0 < d["p"] <= 1, (u, v)
        assert isinstance(d["etype"], str) and d["etype"], (u, v)


def test_edge_counts_by_type(G):
    c = Counter(d["etype"] for _, _, d in G.edges(data=True))
    assert c["CAN_ESCALATE"] == 1
    assert c["DIRECT_ADMIN"] == 0
    assert c["CAN_ACCESS"] == 2
    assert c["CAN_ASSUME"] == 2
    assert c["USES_KEY"] == 2          # raynor active + scanner active
    assert c["HAS_POLICY"] == 3        # raynor, role A, role B (scanner has no targets)
    assert c["HAS_STATEMENT"] == 3
    assert c["INTERNET_TO_RANGE"] == 1
    assert c["RANGE_TO_RULE"] == 3     # ssh, all, web (icmp ignored)
    assert c["RULE_TO_SG"] == 3
    assert c["SG_TO_VPC"] == 1


# ----------------------------------------------------------------------------
# Attack paths
# ----------------------------------------------------------------------------

def test_raynor_shaped_fixture_reaches_admin(G):
    assert G.has_edge(STMT_RAYNOR, ADMIN)
    assert G[STMT_RAYNOR][ADMIN]["etype"] == "CAN_ESCALATE"
    assert G[STMT_RAYNOR][ADMIN]["p"] == TEST_PRIV["iam:SetDefaultPolicyVersion"]
    assert nx.has_path(G, USER_RAYNOR, ADMIN)
    assert nx.has_path(G, "KEY:" + KEY_RAYNOR, ADMIN)
    path = nx.shortest_path(G, "KEY:" + KEY_RAYNOR, ADMIN)
    assert path == ["KEY:" + KEY_RAYNOR, USER_RAYNOR, POL_RAYNOR, STMT_RAYNOR, ADMIN]


def test_scanner_has_no_path_to_admin(G):
    assert not nx.has_path(G, USER_SCAN, ADMIN)
    assert not nx.has_path(G, "KEY:" + KEY_SCAN, ADMIN)


def test_near_and_far_hop_counts(G):
    assert nx.shortest_path_length(G, USER_TEST, BUCKET_NEAR) == 4   # user>roleA>policy>stmt>bucket
    assert nx.shortest_path_length(G, USER_TEST, BUCKET_FAR) == 5    # one extra role hop
    assert not nx.has_path(G, USER_TEST, ADMIN)


def test_network_branch(G):
    assert G[INTERNET][RANGE_V4]["etype"] == "INTERNET_TO_RANGE"
    assert G["sg-111/in/tcp/22"]["sg-111"]["p"] == TEST_W["net_sensitive_port"]
    assert G["sg-222/in/all"]["sg-222"]["p"] == TEST_W["net_all_ports"]
    assert G["sg-333/in/tcp/80"]["sg-333"]["p"] == TEST_W["net_web_port"]
    assert "sg-444/in/icmp" not in G and "sg-444" not in G        # ICMP ignored
    assert nx.has_path(G, INTERNET, "vpc-aaa")
    assert "sg-999" not in G                                       # unexposed group never added


def test_net_query_matches_inbound_rules_only():
    assert "AWSIpPermissionInbound" in ag.Q_NET
    assert "Egress" not in ag.Q_NET


# ----------------------------------------------------------------------------
# Entry nodes and crown jewels
# ----------------------------------------------------------------------------

def test_entry_nodes_seed_keys_and_plain_users(G):
    entries = resolve_entry_nodes(G, TEST_CFG)
    assert INTERNET in entries
    assert "KEY:" + KEY_RAYNOR in entries      # user with an active key is seeded via the key
    assert USER_RAYNOR not in entries
    assert USER_TEST in entries                # user without keys is seeded directly


def test_scanner_is_never_an_entry_even_if_listed(G):
    cfg = copy.deepcopy(TEST_CFG)
    cfg["entry_nodes"] = cfg["entry_nodes"] + [SCANNER_NAME, USER_SCAN]
    entries = resolve_entry_nodes(G, cfg)
    assert USER_SCAN not in entries
    assert "KEY:" + KEY_SCAN not in entries


def test_crown_jewels_include_admin_and_flagged_buckets(G):
    jewels = get_crown_jewels(G, TEST_CFG)
    assert ADMIN in jewels
    assert BUCKET_NEAR in jewels               # flagged by node property
    assert BUCKET_FAR in jewels                # flagged by tag node
    assert G.nodes[BUCKET_NEAR]["personal_data"] is True
    assert G.nodes[BUCKET_FAR]["personal_data"] is True


def test_manual_crown_jewel_fallback_when_tags_missing():
    rows = _rows()
    rows[ag.Q_BUCKET_TAGS] = []                # tags not stored by Cartography
    rows[ag.Q_BUCKETS][0]["props"] = {"name": "argus-test-pii-near-fake1234"}
    G2 = _graph(rows)
    assert get_crown_jewels(G2, TEST_CFG) == [ADMIN]
    cfg = copy.deepcopy(TEST_CFG)
    cfg["crown_jewel_ids"] = ["argus-test-pii-near-fake1234", BUCKET_FAR]   # by label and by id
    assert get_crown_jewels(G2, cfg) == sorted([ADMIN, BUCKET_NEAR, BUCKET_FAR])


# ----------------------------------------------------------------------------
# Statement logic
# ----------------------------------------------------------------------------

def test_direct_admin_statement():
    t = _statement_targets(["*"], ["*"], [], TEST_W, TEST_PRIV)
    assert t == [(ADMIN, 1.0, "DIRECT_ADMIN")]


def test_escalation_needs_iam_or_wildcard_resource_scope():
    on_bucket = _statement_targets(["iam:SetDefaultPolicyVersion"], ["arn:aws:s3:::foo"], [], TEST_W, TEST_PRIV)
    assert on_bucket == []
    on_policy = _statement_targets(
        ["iam:SetDefaultPolicyVersion"], ["arn:aws:iam::1:policy/p"], [], TEST_W, TEST_PRIV)
    assert on_policy == [(ADMIN, 0.85, "CAN_ESCALATE")]


def test_best_escalation_probability_is_used():
    t = _statement_targets(["iam:*"], ["*"], [], TEST_W, TEST_PRIV)
    assert t == [(ADMIN, 0.9, "CAN_ESCALATE")]


def test_read_vs_write_weight_and_scope():
    b = "arn:aws:s3:::x"
    assert _statement_targets(["s3:PutObject"], [b + "/*"], [b], TEST_W, TEST_PRIV) == [(b, 0.7, "CAN_ACCESS")]
    assert _statement_targets(["s3:GetObject"], ["*"], [b], TEST_W, TEST_PRIV) == [(b, 0.8, "CAN_ACCESS")]
    assert _statement_targets(["s3:GetObject"], ["arn:aws:s3:::other/*"], [b], TEST_W, TEST_PRIV) == []


def test_statement_without_action_creates_nothing():
    rows = _rows()
    rows[ag.Q_STATEMENTS] = [{
        "pid": USER_TEST, "polid": POL_NEAR, "polname": "n", "stmt_id": STMT_NEAR,
        "stmt_sid": None, "effect": "Allow", "action": None, "resource": ["*"]}]
    G2 = _graph(rows)
    assert STMT_NEAR not in G2


def test_port_probabilities():
    assert _port_p(22, 22, "tcp", TEST_W) == 0.9
    assert _port_p(0, 65535, "tcp", TEST_W) == 0.95
    assert _port_p(None, None, "-1", TEST_W) == 0.95
    assert _port_p(1000, 2000, "tcp", TEST_W) == 0.9        # range 1000-2000 contains 1433
    assert _port_p(443, 443, "tcp", TEST_W) == 0.4
    assert _port_p(-1, -1, "icmp", TEST_W) is None


# ----------------------------------------------------------------------------
# Config validation and safety
# ----------------------------------------------------------------------------

def test_missing_weight_key_fails_loudly():
    bad = dict(TEST_W)
    del bad["can_assume"]
    with pytest.raises(ValueError, match="can_assume"):
        _check_weights(bad)


def test_out_of_range_weight_fails():
    bad = dict(TEST_W, s3_read=0)
    with pytest.raises(ValueError):
        _check_weights(bad)
    with pytest.raises(ValueError):
        _check_privesc({"iam:PassRole": 1.5})


def test_real_config_files_are_valid_if_present():
    d = Path(ag.__file__).resolve().parent
    needed = [d / "edge_weights.json", d / "privesc_actions.json", d / "config.json"]
    if not all(p.exists() for p in needed):
        pytest.skip("config files not on this branch yet")
    _check_weights(ag._load_json("edge_weights.json"))
    _check_privesc(ag._load_json("privesc_actions.json")["actions"])
    cfg = ag._load_json("config.json")
    assert "entry_nodes" in cfg and "excluded_principals" in cfg


def test_queries_are_read_only():
    forbidden = re.compile(r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|CALL|LOAD)\b", re.IGNORECASE)
    for q in ag.ALL_QUERIES:
        assert not forbidden.search(q), q


def test_every_query_is_actually_issued():
    session = FakeSession(_rows())
    _build(session, TEST_W, TEST_PRIV, TEST_CFG)
    assert set(session.seen) == set(ag.ALL_QUERIES)


def test_source_has_no_hardcoded_identifiers():
    src = Path(ag.__file__).read_text(encoding="utf-8")
    assert not re.search(r"\b\d{12}\b", src), "12-digit account id found"
    assert "cgid" not in src.lower()
    assert "argus-cartography-scanner" not in src
    assert "argus-test" not in src
    assert not re.search(r"arn:aws:iam::", src)