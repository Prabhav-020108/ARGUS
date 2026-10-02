"""
Tests for the frozen config files in risk/.

These guard the heuristics: if someone edits a weight into an invalid range,
or accidentally makes the scanner user an attack entry point, CI fails.
"""

import glob
import json
import pathlib

RISK_DIR = pathlib.Path(__file__).resolve().parent.parent


def _load(name):
    return json.loads((RISK_DIR / name).read_text(encoding="utf-8"))


def test_all_json_files_parse():
    files = glob.glob(str(RISK_DIR / "*.json"))
    assert files, "no JSON files found in risk/"
    for f in files:
        json.loads(pathlib.Path(f).read_text(encoding="utf-8"))


def test_edge_weights_are_numbers_in_range():
    weights = _load("edge_weights.json")
    for key, val in weights.items():
        if isinstance(val, list):
            continue
        assert isinstance(val, (int, float)) and not isinstance(val, bool), key
        assert 0 < val <= 1, "{} = {} is outside (0, 1]".format(key, val)


def test_sensitive_ports_is_list_of_ints():
    ports = _load("edge_weights.json")["sensitive_ports"]
    assert isinstance(ports, list) and ports
    assert all(isinstance(p, int) and not isinstance(p, bool) for p in ports)
    assert all(0 < p <= 65535 for p in ports)


def test_privesc_actions_valid():
    data = _load("privesc_actions.json")
    assert isinstance(data.get("actions"), dict) and data["actions"]
    for action, p in data["actions"].items():
        assert ":" in action, "{} is not a service:Action string".format(action)
        assert isinstance(p, (int, float)) and 0 < p <= 1, action


def test_raynor_rollback_action_present():
    assert "iam:SetDefaultPolicyVersion" in _load("privesc_actions.json")["actions"]


def test_entry_nodes_non_empty():
    cfg = _load("config.json")
    assert isinstance(cfg["entry_nodes"], list) and cfg["entry_nodes"]


def test_scanner_excluded_and_not_an_entry():
    cfg = _load("config.json")
    assert "argus-cartography-scanner" in cfg["excluded_principals"]
    assert "argus-cartography-scanner" not in cfg["entry_nodes"]


def test_damping_in_open_interval():
    d = _load("damping_config.json")["damping"]
    assert 0 < d < 1
