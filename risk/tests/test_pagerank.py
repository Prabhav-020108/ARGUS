"""
Tests for risk/pagerank.py.

All analytical closed forms were derived before writing this file and are
independent of the implementation.  Do NOT weaken tolerances; fix the code.
"""

import numpy as np
import networkx as nx
import pytest

from risk.pagerank import _with_absorb, ppr_power_iteration, score_digraph, ABSORB


# ---------------------------------------------------------------------------
# Shared toy graph
# ---------------------------------------------------------------------------

def _toy() -> nx.DiGraph:
    """Minimal attack graph for testing.  Built with raw networkx only."""
    G = nx.DiGraph()
    G.add_node("S",          kind="key",    label="S")
    G.add_node("U",          kind="user",   label="U")
    G.add_node("POL",        kind="policy", label="POL")
    G.add_node("STM",        kind="stmt",   label="STM")
    G.add_node("ADMIN_EQUIV",kind="admin",  label="ADMIN_EQUIV")
    G.add_node("BUCKET",     kind="bucket", label="BUCKET", personal_data=True)

    G.add_edge("S",   "U",          p=0.9,  etype="USES_KEY")
    G.add_edge("U",   "POL",        p=1.0,  etype="HAS_POLICY")
    G.add_edge("POL", "STM",        p=1.0,  etype="HAS_STATEMENT")
    G.add_edge("STM", "ADMIN_EQUIV",p=0.85, etype="CAN_ESCALATE")
    G.add_edge("STM", "BUCKET",     p=0.8,  etype="CAN_ACCESS")
    return G


# ---------------------------------------------------------------------------
# Test 1 — Two-node closed form
# ---------------------------------------------------------------------------

def test_ppr_two_node_closed_form():
    """pi[A] = 1/1.85, pi[B] = 0.85/1.85 for a single A->B w=1 edge."""
    H = nx.DiGraph()
    H.add_edge("A", "B", w=1.0)

    pi = ppr_power_iteration(H, {"A": 1.0}, alpha=0.85)

    assert abs(pi["A"] - 1.0 / 1.85) < 1e-9, f"pi[A]={pi['A']}"
    assert abs(pi["B"] - 0.85 / 1.85) < 1e-9, f"pi[B]={pi['B']}"


# ---------------------------------------------------------------------------
# Test 2 — Three-node chain closed form
# ---------------------------------------------------------------------------

def test_ppr_three_node_chain():
    """pi[A]=(1-α)/(1-α³), pi[B]=α*pi[A], pi[C]=α*pi[B]."""
    H = nx.DiGraph()
    H.add_edge("A", "B", w=1.0)
    H.add_edge("B", "C", w=1.0)

    alpha = 0.85
    pi = ppr_power_iteration(H, {"A": 1.0}, alpha=alpha)

    expected_A = (1.0 - alpha) / (1.0 - alpha ** 3)
    expected_B = alpha * expected_A
    expected_C = alpha * expected_B

    assert abs(pi["A"] - expected_A) < 1e-9, f"pi[A]={pi['A']}"
    assert abs(pi["B"] - expected_B) < 1e-9, f"pi[B]={pi['B']}"
    assert abs(pi["C"] - expected_C) < 1e-9, f"pi[C]={pi['C']}"


# ---------------------------------------------------------------------------
# Test 3 — Higher p gives higher score
# ---------------------------------------------------------------------------

def test_higher_p_gives_higher_score():
    """From one source, the node with p=0.9 outscores the one with p=0.1."""
    G = nx.DiGraph()
    G.add_node("S", kind="source", label="S")
    G.add_node("X", kind="target", label="X")
    G.add_node("Y", kind="target", label="Y")
    G.add_edge("S", "X", p=0.9, etype="FOO")
    G.add_edge("S", "Y", p=0.1, etype="FOO")

    pi = score_digraph(G, entry_nodes=["S"])

    assert pi["X"] > pi["Y"]


# ---------------------------------------------------------------------------
# Test 4 — Weak edge gives lower score than strong edge
# ---------------------------------------------------------------------------

def test_weak_edge_gives_lower_score_than_strong():
    """score(T | p=0.1) < score(T | p=0.9) for a lone S->T edge."""

    def _make(p_val: float) -> nx.DiGraph:
        G = nx.DiGraph()
        G.add_node("S", kind="source", label="S")
        G.add_node("T", kind="target", label="T")
        G.add_edge("S", "T", p=p_val, etype="FOO")
        return G

    pi_low  = score_digraph(_make(0.1), entry_nodes=["S"])
    pi_high = score_digraph(_make(0.9), entry_nodes=["S"])

    assert pi_low["T"] < pi_high["T"]


# ---------------------------------------------------------------------------
# Test 5 — Match networkx.pagerank
# ---------------------------------------------------------------------------

def test_ppr_matches_networkx():
    """Our power iteration must agree with networkx.pagerank to within 1e-6."""
    G = _toy()
    H = _with_absorb(G)

    my_pi = ppr_power_iteration(
        H,
        personalization={"S": 1.0},
        alpha=0.85,
        tol=1e-12,
        max_iter=1000,
    )
    nx_pi = nx.pagerank(
        H,
        alpha=0.85,
        personalization={"S": 1.0},
        weight="w",
        dangling={"S": 1.0},
        tol=1e-12,
        max_iter=1000,
    )

    for node in H.nodes():
        diff = abs(my_pi[node] - nx_pi[node])
        assert diff < 1e-6, (
            f"Node {node!r}: my={my_pi[node]:.14f}  nx={nx_pi[node]:.14f}  "
            f"diff={diff:.2e}"
        )


# ---------------------------------------------------------------------------
# Test 6 — PPR scores sum to 1 (including ABSORB)
# ---------------------------------------------------------------------------

def test_ppr_scores_sum_to_one():
    """sum over ALL nodes in H (including ABSORB) must be 1 within 1e-9."""
    G = _toy()
    H = _with_absorb(G)
    pi = ppr_power_iteration(H, {"S": 1.0}, alpha=0.85)

    total = sum(pi.values())
    assert abs(total - 1.0) < 1e-9, f"sum(pi)={total}"


# ---------------------------------------------------------------------------
# Test 7 — score_digraph correctness and validation
# ---------------------------------------------------------------------------

def test_score_digraph_excludes_absorb():
    """ABSORB must not appear in the dict returned by score_digraph."""
    pi = score_digraph(_toy(), entry_nodes=["S"])
    assert ABSORB not in pi


def test_score_digraph_does_not_mutate_graph():
    """score_digraph must leave G's edge data untouched."""
    G = _toy()
    edges_before = [(u, v, dict(d)) for u, v, d in G.edges(data=True)]
    score_digraph(G, entry_nodes=["S"])
    edges_after = [(u, v, dict(d)) for u, v, d in G.edges(data=True)]
    assert edges_before == edges_after


def test_score_digraph_invalid_damping_zero():
    with pytest.raises(ValueError, match="damping"):
        score_digraph(_toy(), entry_nodes=["S"], damping=0)


def test_score_digraph_invalid_damping_one():
    with pytest.raises(ValueError, match="damping"):
        score_digraph(_toy(), entry_nodes=["S"], damping=1)


def test_score_digraph_empty_entry_list():
    with pytest.raises(ValueError):
        score_digraph(_toy(), entry_nodes=[])


def test_score_digraph_edge_with_p_zero():
    G = nx.DiGraph()
    G.add_node("S", kind="source", label="S")
    G.add_node("T", kind="target", label="T")
    G.add_edge("S", "T", p=0.0, etype="FOO")
    with pytest.raises(ValueError, match="p"):
        score_digraph(G, entry_nodes=["S"])


# ---------------------------------------------------------------------------
# Test 8 — Damping default equals explicit 0.85
# ---------------------------------------------------------------------------

def test_damping_default_equals_explicit_085():
    """Reading default from config must give the same result as passing 0.85."""
    G = _toy()
    pi_default  = score_digraph(G, entry_nodes=["S"])
    pi_explicit = score_digraph(G, entry_nodes=["S"], damping=0.85)

    for node in pi_default:
        assert pi_default[node] == pytest.approx(pi_explicit[node]), (
            f"Node {node!r}: default={pi_default[node]}  explicit={pi_explicit[node]}"
        )
