"""
Path utilities for ARGUS Phase 2 risk engine.

Provides shortest / most-probable path helpers that operate on the
derived attack graph produced by risk.attack_graph.

All functions are read-only with respect to the graph.
"""

import math
from typing import Optional

import networkx as nx


def most_probable_path(
    G: nx.DiGraph,
    source: str,
    target: str,
) -> tuple[list[str], float]:
    """Return the most probable path from *source* to *target* in *G*.

    Uses Dijkstra on ``-log(p)`` edge lengths so that the shortest
    path in log-space corresponds to the highest product of edge
    probabilities in linear space.

    Parameters
    ----------
    G:
        Directed attack graph whose edges carry a ``p`` attribute in
        ``(0, 1]``.
    source:
        Node ID of the starting node.
    target:
        Node ID of the destination node.

    Returns
    -------
    tuple[list[str], float]
        A 2-tuple ``(path, probability)`` where *path* is the ordered
        list of node IDs from *source* to *target* (inclusive) and
        *probability* is the product of edge ``p`` values along that
        path.

    Raises
    ------
    nx.NetworkXNoPath
        If no path exists between *source* and *target*.
    nx.NodeNotFound
        If either node is absent from *G*.
    """
    # Build a log-length view (avoids mutating G).
    H: nx.DiGraph = nx.DiGraph()
    H.add_nodes_from(G.nodes(data=True))
    for u, v, d in G.edges(data=True):
        p_raw = d.get("p", 1.0)
        p_val = max(min(float(p_raw), 1.0), 1e-12)
        H.add_edge(u, v, len=-math.log(p_val), p=p_val)

    path: list[str] = nx.shortest_path(
        H, source=source, target=target, weight="len"
    )

    p_prod = 1.0
    for u, v in zip(path[:-1], path[1:]):
        p_prod *= H[u][v].get("p", 1.0)

    return path, p_prod


def all_paths_to_target(
    G: nx.DiGraph,
    sources: list[str],
    target: str,
    cutoff: Optional[int] = None,
) -> list[tuple[list[str], float]]:
    """Return all simple paths from any node in *sources* to *target*.

    Each result is a ``(path, probability)`` pair.  Results are sorted
    by descending probability.  Use *cutoff* to limit path length and
    avoid combinatorial explosion on large graphs.

    Parameters
    ----------
    G:
        Directed attack graph with ``p`` edge attributes.
    sources:
        List of entry-node IDs.
    target:
        Destination node ID (e.g. ``"ADMIN_EQUIV"``).
    cutoff:
        Maximum path length (number of edges).  ``None`` means
        unlimited — be careful on large graphs.

    Returns
    -------
    list[tuple[list[str], float]]
        Sorted list of ``(path, probability)`` pairs, highest
        probability first.
    """
    results: list[tuple[list[str], float]] = []
    for src in sources:
        if src not in G or target not in G:
            continue
        for path in nx.all_simple_paths(G, src, target, cutoff=cutoff):
            p_prod = 1.0
            for u, v in zip(path[:-1], path[1:]):
                p_prod *= G[u][v].get("p", 1.0)
            results.append((list(path), p_prod))

    results.sort(key=lambda x: x[1], reverse=True)
    return results
