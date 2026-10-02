"""
Validation runner for ARGUS Phase 2 Risk Engine.

Verifies attack graph properties, Personalized PageRank scoring,
and path discovery against ground truth definitions without manual intervention.
"""

from collections import Counter
import json
import math
import os
import pathlib
import re
import networkx as nx


def _mask_text(text: str) -> str:
    """Mask account IDs, ARNs, and key IDs."""
    if not text:
        return text
    s = str(text)
    # Mask AWS access key IDs (AKIA..., ASIA...)
    s = re.sub(r"\b(AKIA|ASIA)[0-9A-Z]{12}([0-9A-Z]{4})\b", r"****\2", s)
    # Mask full ARNs: replace account ID segment with ***
    s = re.sub(r"arn:aws:([a-z0-9-]+):([a-z0-9-]*):\d{12}:([^\s\"']+)", r"arn:aws:\1:\2:***:\3", s)
    # Mask any standalone 12-digit account IDs
    s = re.sub(r"\b\d{12}\b", r"************", s)
    return s


def _mask_node(G, n) -> str:
    """Return masked label for a node, masking key IDs as ****last4."""
    data = G.nodes.get(n, {})
    kind = data.get("kind", "")
    lbl = data.get("label", str(n))
    if kind == "key":
        return f"****{lbl[-4:]}"
    return _mask_text(lbl)


def main() -> int:
    # 1. Verification of Neo4j credentials
    if "NEO4J_PASSWORD" not in os.environ:
        print("Set $env:NEO4J_PASSWORD first")
        return 2

    # Driver initialization
    try:
        from risk.graph_loader import get_driver
        driver = get_driver()
    except (ImportError, AttributeError):
        import neo4j
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        pw = os.environ["NEO4J_PASSWORD"]
        driver = neo4j.GraphDatabase.driver(uri, auth=(user, pw))

    # 2. Lazy imports and graph construction
    try:
        from risk.attack_graph import build_attack_graph, resolve_entry_nodes, get_crown_jewels, ADMIN
    except ImportError:
        print("validate.py: waiting for P1's attack_graph.py to be merged")
        return 2

    try:
        with driver.session() as session:
            G = build_attack_graph(session)
    except NotImplementedError:
        print("validate.py: waiting for P1's attack_graph.py to be merged")
        return 2

    from risk.pagerank import score_digraph

    # 3. Graph topology diagnostics
    print(f"Node count: {G.number_of_nodes()}")
    print(f"Edge count: {G.number_of_edges()}")
    etype_counts = Counter(d.get("etype", "UNKNOWN") for _, _, d in G.edges(data=True))
    print("Edge count per etype:")
    for etype, count in sorted(etype_counts.items()):
        print(f"  {etype}: {count}")

    # 4. Entry node and crown jewel resolution
    entry = resolve_entry_nodes(G)
    print("\nEntry nodes:")
    for e in entry:
        data = G.nodes.get(e, {})
        kind = data.get("kind", "")
        print(f"  {_mask_node(G, e)} (kind: {kind})")

    crown_jewels = get_crown_jewels(G)
    print("\nCrown jewels:")
    for cj in crown_jewels:
        data = G.nodes.get(cj, {})
        kind = data.get("kind", "")
        print(f"  {_mask_node(G, cj)} (kind: {kind})")

    pi = score_digraph(G, entry)

    # 5. Top 15 ranked nodes
    sorted_nodes = sorted(pi.items(), key=lambda kv: kv[1], reverse=True)
    print("\nTop 15 nodes by score:")
    for node_id, score in sorted_nodes[:15]:
        node_data = G.nodes.get(node_id, {})
        kind = node_data.get("kind", "unknown")
        masked_lbl = _mask_node(G, node_id)
        print(f"  {score:.5f} | {kind} | {masked_lbl}")

    # Load configuration and ground-truth specifications relative to this file
    risk_dir = pathlib.Path(__file__).resolve().parent
    repo_root = risk_dir.parent
    config_file = risk_dir / "config.json"
    gt_file = repo_root / "testbeds" / "cloudgoat" / "ground_truth_paths.json"

    with open(config_file, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    with open(gt_file, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    # 6. Directed path graph with log transformation: len = -log(p)
    H = nx.DiGraph()
    H.add_nodes_from(G.nodes(data=True))
    for u, v, d in G.edges(data=True):
        p = d.get("p", 1.0)
        p_val = max(min(float(p), 1.0), 1e-12)
        H.add_edge(u, v, len=-math.log(p_val), p=p_val)

    admin_node = ADMIN if ADMIN in G else "ADMIN_EQUIV"

    try:
        from risk.paths import most_probable_path
        has_mpp = True
    except (ImportError, AttributeError):
        has_mpp = False

    print("\nPaths from entry nodes to ADMIN:")
    for e in entry:
        if e in H and admin_node in H and nx.has_path(H, e, admin_node):
            if has_mpp:
                mpp_res = most_probable_path(G, e, admin_node)
                path = mpp_res[0] if isinstance(mpp_res, tuple) else mpp_res
            else:
                path = nx.shortest_path(H, source=e, target=admin_node, weight="len")
            path_labels = [_mask_node(G, n) for n in path]
            p_prod = 1.0
            for u, v in zip(path[:-1], path[1:]):
                p_prod *= H[u][v].get("p", 1.0)
            print(f"  Entry {_mask_node(G, e)}: {' -> '.join(path_labels)} (p_prod={p_prod:.5f})")

    # 7. Acceptance checks
    check_a_pass = False
    check_b_pass = False
    check_c_pass = False

    # (a) ADMIN_EQUIV rank by score
    rank_all = None
    for idx, (n, _) in enumerate(sorted_nodes, start=1):
        if n == admin_node or G.nodes.get(n, {}).get("label") == "ADMIN_EQUIV":
            rank_all = idx
            break

    cfg_entries = set(config_data.get("entry_nodes", []))
    all_entry = set(entry)
    for n, d in G.nodes(data=True):
        if n in cfg_entries or d.get("label") in cfg_entries:
            all_entry.add(n)

    filtered_ranked = [
        (n, s) for n, s in sorted_nodes
        if n not in all_entry and n != "INTERNET"
        and G.nodes.get(n, {}).get("label") != "INTERNET"
        and G.nodes.get(n, {}).get("kind") != "internet"
    ]
    rank_excl = None
    for idx, (n, _) in enumerate(filtered_ranked, start=1):
        if n == admin_node or G.nodes.get(n, {}).get("label") == "ADMIN_EQUIV":
            rank_excl = idx
            break

    if rank_all is not None and rank_excl is not None:
        print(f"\nADMIN_EQUIV rank: all={rank_all}, excluding entry/INTERNET={rank_excl}")
        if rank_excl <= 3:
            check_a_pass = True
            print(f"Check (a) PASS: ADMIN_EQUIV rank excluding entry/INTERNET is {rank_excl} (<= 3)")
        else:
            print(f"Check (a) FAIL: ADMIN_EQUIV rank excluding entry/INTERNET is {rank_excl} (> 3)")
    else:
        print("\nCheck (a) FAIL: ADMIN_EQUIV node not found in scored nodes")

    # (b) Path matches ground truth (ignoring nodes of kind 'key')
    gt_entries = gt_data.get("entry", [])
    expected_path_labels = gt_data.get("expected_path_labels", [])
    gt_entry_label = gt_entries[0] if gt_entries else None

    found_path = None
    # Check paths originating from resolved entry nodes
    for e in entry:
        if admin_node in H and nx.has_path(H, e, admin_node):
            p = nx.shortest_path(H, source=e, target=admin_node, weight="len")
            # Strip key nodes per requirement (iii)
            p_trimmed = [n for n in p if G.nodes.get(n, {}).get("kind") != "key"]
            if p_trimmed and (G.nodes.get(p_trimmed[0], {}).get("label") == gt_entry_label or p_trimmed[0] == gt_entry_label):
                found_path = p_trimmed
                break

    # Fallback: check path from the gt_entry_label node itself in G
    if found_path is None:
        gt_node = None
        for n, data in G.nodes(data=True):
            if data.get("label") == gt_entry_label or n == gt_entry_label:
                gt_node = n
                break
        if gt_node is not None and admin_node in H and nx.has_path(H, gt_node, admin_node):
            p = nx.shortest_path(H, source=gt_node, target=admin_node, weight="len")
            found_path = [n for n in p if G.nodes.get(n, {}).get("kind") != "key"]

    if found_path is None:
        print(f"Check (b) FAIL: No valid path found from ground-truth entry '{gt_entry_label}' to {admin_node}")
    else:
        actual_labels = [G.nodes.get(n, {}).get("label", str(n)) for n in found_path]
        has_wildcard = any(lbl.startswith("<") for lbl in expected_path_labels)
        if has_wildcard:
            print("NOTE: statement label is still a placeholder wildcard in expected path")

        lengths_match = len(actual_labels) == len(expected_path_labels)
        labels_match = lengths_match and all(
            exp.startswith("<") or act == exp
            for act, exp in zip(actual_labels, expected_path_labels)
        )
        masked_actual = [_mask_node(G, n) for n in found_path]
        if labels_match:
            check_b_pass = True
            print(f"Check (b) PASS: Path labels match ground truth: {' -> '.join(masked_actual)}")
        else:
            print(f"Check (b) FAIL: Path {masked_actual} does not match expected {expected_path_labels}")

    # (c) Scanner control check
    excluded_principals = config_data.get("excluded_principals", [])
    scanner_name = excluded_principals[0] if excluded_principals else "argus-cartography-scanner"

    scanner_node = None
    for n, data in G.nodes(data=True):
        if data.get("label") == scanner_name or n == scanner_name:
            scanner_node = n
            break

    if scanner_node is None:
        check_c_pass = True
        print(f"Check (c) PASS: Scanner principal '{_mask_text(scanner_name)}' is absent from the attack graph")
    else:
        path_from_scanner = admin_node in H and nx.has_path(H, scanner_node, admin_node)
        key_preds = [
            u for u, v, _ in G.in_edges(scanner_node, data=True)
            if G.nodes.get(u, {}).get("kind") == "key"
        ]
        path_from_key = any(admin_node in H and nx.has_path(H, k, admin_node) for k in key_preds)

        if not path_from_scanner and not path_from_key:
            check_c_pass = True
            print(f"Check (c) PASS: Scanner principal '{_mask_text(scanner_name)}' has NO path to {admin_node}")
        else:
            print(f"Check (c) FAIL: Found path from scanner principal '{_mask_text(scanner_name)}' or its key to {admin_node}")

    # 8. Summary verdict
    res_a = "PASS" if check_a_pass else "FAIL"
    res_b = "PASS" if check_b_pass else "FAIL"
    res_c = "PASS" if check_c_pass else "FAIL"
    print(f"\nFinal Summary: Check (a) [{res_a}], Check (b) [{res_b}], Check (c) [{res_c}]")

    return 0 if (check_a_pass and check_b_pass and check_c_pass) else 1


if __name__ == "__main__":
    raise SystemExit(main())
