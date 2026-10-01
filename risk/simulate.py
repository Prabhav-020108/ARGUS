"""
ARGUS Phase 2 — Graph-patch simulator.

``apply_delta(G, delta)`` applies a sequence of patch operations to a *copy*
of G.  **G is never mutated.**

Supported ops
-------------
``remove_policy_statement``
    Remove every outgoing edge of ``target`` whose ``etype`` is in
    ``{"CAN_ESCALATE", "DIRECT_ADMIN", "CAN_ACCESS"}``.
    If ``target`` is not in the graph, do nothing.

``restrict_cidr``
    For every *incoming* edge of ``target`` whose ``etype`` is
    ``"RULE_TO_SG"``, multiply the edge's ``p`` attribute by ``factor``
    (default 0.1), clamped to a minimum of 1e-6.
    If ``target`` is not in the graph, do nothing.

Any other op
    **No graph effect.**  Unknown operation strings are silently ignored;
    they do not raise an exception.
"""

import networkx as nx

_ADMIN_ETYPES: frozenset = frozenset({"CAN_ESCALATE", "DIRECT_ADMIN", "CAN_ACCESS"})
_RULE_TO_SG: str = "RULE_TO_SG"
_P_FLOOR: float = 1e-6


def apply_delta(G: nx.DiGraph, delta: dict) -> nx.DiGraph:
    """Apply a delta (list of ops) to a copy of G.

    Parameters
    ----------
    G : nx.DiGraph
        Source graph.  **Never mutated.**
    delta : dict
        ``{"ops": [{"op": str, "target": node_id, "factor": float}, ...]}``.
        ``factor`` is optional (used only by ``restrict_cidr``; default 0.1).

    Returns
    -------
    nx.DiGraph
        A modified copy of G with all recognised ops applied.
    """
    H: nx.DiGraph = G.copy()

    for op_spec in delta.get("ops", []):
        op = op_spec.get("op")
        target = op_spec.get("target")

        if op == "remove_policy_statement":
            if target not in H:
                continue
            # Collect first, then remove — avoids mutating dict during iteration.
            edges_to_remove = [
                (target, v)
                for v, data in list(H[target].items())
                if data.get("etype") in _ADMIN_ETYPES
            ]
            H.remove_edges_from(edges_to_remove)

        elif op == "restrict_cidr":
            if target not in H:
                continue
            factor = float(op_spec.get("factor", 0.1))
            for u, _, data in list(H.in_edges(target, data=True)):
                if data.get("etype") == _RULE_TO_SG:
                    new_p = max(data.get("p", 1.0) * factor, _P_FLOOR)
                    H[u][target]["p"] = new_p

        # Any other op: no graph effect (silently ignored).

    return H
