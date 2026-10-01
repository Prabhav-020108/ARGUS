"""
Tests for risk/simulate.py.
"""

import networkx as nx
import pytest

from risk.pagerank import score_digraph
from risk.simulate import apply_delta


def _toy() -> nx.DiGraph:
    """Minimal attack graph for testing. Built with raw networkx only."""
    G = nx.DiGraph()
    G.add_node("S", kind="key", label="S")
    G.add_node("U", kind="user", label="U")
    G.add_node("POL", kind="policy", label="POL")
    G.add_node("STM", kind="stmt", label="STM")
    G.add_node("ADMIN_EQUIV", kind="admin", label="ADMIN_EQUIV")
    G.add_node("BUCKET", kind="bucket", label="BUCKET", personal_data=True)

    G.add_edge("S", "U", p=0.9, etype="USES_KEY")
    G.add_edge("U", "POL", p=1.0, etype="HAS_POLICY")
    G.add_edge("POL", "STM", p=1.0, etype="HAS_STATEMENT")
    G.add_edge("STM", "ADMIN_EQUIV", p=0.85, etype="CAN_ESCALATE")
    G.add_edge("STM", "BUCKET", p=0.8, etype="CAN_ACCESS")
    return G


def test_simulate():
    """Requirement 9:

    - apply_delta removing CAN_ESCALATE edge of STM lowers the ADMIN_EQUIV score vs the original (entry ["S"])
    - original graph still has that edge afterwards
    - restrict_cidr on a small graph (RANGE->RULE->SG with etype RULE_TO_SG) lowers p by the factor
    - unknown op leaves the graph unchanged
    """
    # 1. remove_policy_statement lowers ADMIN_EQUIV score & preserves original graph
    G = _toy()
    orig_scores = score_digraph(G, entry_nodes=["S"])

    delta_remove = {
        "ops": [
            {"op": "remove_policy_statement", "target": "STM"}
        ]
    }
    H = apply_delta(G, delta_remove)
    patched_scores = score_digraph(H, entry_nodes=["S"])

    assert patched_scores["ADMIN_EQUIV"] < orig_scores["ADMIN_EQUIV"]
    assert ("STM", "ADMIN_EQUIV") not in H.edges
    assert ("STM", "ADMIN_EQUIV") in G.edges
    assert G["STM"]["ADMIN_EQUIV"]["p"] == 0.85
    assert G["STM"]["ADMIN_EQUIV"]["etype"] == "CAN_ESCALATE"

    # 2. restrict_cidr on small graph (RANGE->RULE->SG with etype RULE_TO_SG) lowers p by factor
    small_G = nx.DiGraph()
    small_G.add_node("RANGE", kind="range", label="RANGE")
    small_G.add_node("RULE", kind="rule", label="RULE")
    small_G.add_node("SG", kind="sg", label="SG")
    small_G.add_edge("RANGE", "RULE", p=1.0, etype="MEMBER_OF_RULE")
    small_G.add_edge("RULE", "SG", p=0.8, etype="RULE_TO_SG")

    factor = 0.25
    delta_restrict = {
        "ops": [
            {"op": "restrict_cidr", "target": "SG", "factor": factor}
        ]
    }
    small_H = apply_delta(small_G, delta_restrict)

    assert small_H["RULE"]["SG"]["p"] == pytest.approx(0.8 * factor)
    assert small_G["RULE"]["SG"]["p"] == 0.8  # original graph unchanged

    # Test default factor (0.1) as well
    delta_default = {
        "ops": [
            {"op": "restrict_cidr", "target": "SG"}
        ]
    }
    small_H_def = apply_delta(small_G, delta_default)
    assert small_H_def["RULE"]["SG"]["p"] == pytest.approx(0.8 * 0.1)

    # 3. Unknown op leaves the graph unchanged
    delta_unknown = {
        "ops": [
            {"op": "some_unknown_op", "target": "STM", "extra": 123}
        ]
    }
    unchanged_H = apply_delta(G, delta_unknown)
    assert list(unchanged_H.nodes(data=True)) == list(G.nodes(data=True))
    assert list(unchanged_H.edges(data=True)) == list(G.edges(data=True))
