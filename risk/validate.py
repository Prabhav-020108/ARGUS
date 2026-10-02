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
import networkx as nx


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
        from risk.attack_graph import build_attack_graph, resolve_entry_nodes, ADMIN
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

    # 4. Entry node resolution and PageRank calculation
    entry = resolve_entry_nodes(G)
    print("\nEntry nodes:")
    for e in entry:
        lbl = G.nodes.get(e, {}).get("label", str(e))
        print(f"  {e} (label: {lbl})")
    pi = score_digraph(G, entry)

    # 5. Top 15 ranked nodes
    sorted_nodes = sorted(pi.items(), key=lambda kv: kv[1], reverse=True)
    print("\nTop 15 nodes by score:")
    for node_id, score in sorted_nodes[:15]:
        node_data = G.nodes.get(node_id, {})
        kind = node_data.get("kind", "unknown")
        label = node_data.get("label", str(node_id))
        print(f"  {score:.5f} | {kind} | {label}")

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
        if admin_node in H and nx.has_path(H, e, admin_node):
            if has_mpp:
                mpp_res = most_probable_path(G, e, admin_node)
                path = mpp_res[0] if isinstance(mpp_res, tuple) else mpp_res
            else:
                path = nx.shortest_path(H, source=e, target=admin_node, weight="len")
            path_labels = [G.nodes.get(n, {}).get("label", str(n)) for n in path]
            p_prod = 1.0
            for u, v in zip(path[:-1], path[1:]):
                p_prod *= H[u][v].get("p", 1.0)
            print(f"  Entry {e}: {' -> '.join(path_labels)} (p_prod={p_prod:.5f})")

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

    filtered_ranked = [
        (n, s) for n, s in sorted_nodes
        if n not in entry and n != "INTERNET"
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

    # (b) Path matches ground truth
    gt_entries = gt_data.get("entry", [])
    expected_path_labels = gt_data.get("expected_path_labels", [])
    gt_entry_label = gt_entries[0] if gt_entries else None

    gt_node = None
    for n, data in G.nodes(data=True):
        if data.get("label") == gt_entry_label or n == gt_entry_label:
            gt_node = n
            break

    if gt_node is None:
        print(f"Check (b) FAIL: Ground-truth entry '{gt_entry_label}' not found in attack graph")
    elif admin_node not in H or not nx.has_path(H, gt_node, admin_node):
        print(f"Check (b) FAIL: No path from ground-truth entry '{gt_entry_label}' to {admin_node}")
    else:
        best_path = nx.shortest_path(H, source=gt_node, target=admin_node, weight="len")
        start_idx = 0
        while start_idx < len(best_path) and G.nodes.get(best_path[start_idx], {}).get("kind") == "key":
            start_idx += 1
        trimmed_path = best_path[start_idx:]
        actual_labels = [G.nodes.get(n, {}).get("label", str(n)) for n in trimmed_path]

        has_wildcard = any(lbl.startswith("<") for lbl in expected_path_labels)
        if has_wildcard:
            print("NOTE: statement label is still a placeholder wildcard in expected path")

        lengths_match = len(actual_labels) == len(expected_path_labels)
        labels_match = lengths_match and all(
            exp.startswith("<") or act == exp
            for act, exp in zip(actual_labels, expected_path_labels)
        )
        if labels_match:
            check_b_pass = True
            print(f"Check (b) PASS: Path labels match ground truth: {' -> '.join(actual_labels)}")
        else:
            print(f"Check (b) FAIL: Path {actual_labels} does not match expected {expected_path_labels}")

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
        print(f"Check (c) PASS: Scanner principal '{scanner_name}' is absent from the attack graph")
    else:
        path_from_scanner = admin_node in H and nx.has_path(H, scanner_node, admin_node)
        key_preds = [
            u for u, v, _ in G.in_edges(scanner_node, data=True)
            if G.nodes.get(u, {}).get("kind") == "key"
        ]
        path_from_key = any(admin_node in H and nx.has_path(H, k, admin_node) for k in key_preds)

        if not path_from_scanner and not path_from_key:
            check_c_pass = True
            print(f"Check (c) PASS: No path from scanner principal '{scanner_name}' (nor active keys) to {admin_node}")
        else:
            print(f"Check (c) FAIL: Found path from scanner principal '{scanner_name}' or its key to {admin_node}")

    # 8. Summary verdict
    res_a = "PASS" if check_a_pass else "FAIL"
    res_b = "PASS" if check_b_pass else "FAIL"
    res_c = "PASS" if check_c_pass else "FAIL"
    print(f"\nFinal Summary: Check (a) [{res_a}], Check (b) [{res_b}], Check (c) [{res_c}]")

    return 0 if (check_a_pass and check_b_pass and check_c_pass) else 1


if __name__ == "__main__":
    raise SystemExit(main())
