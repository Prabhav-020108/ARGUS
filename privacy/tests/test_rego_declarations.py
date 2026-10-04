"""Guards the conventions the projection layer depends on, and the DPDP mapping coverage."""

import re
from pathlib import Path

from privacy.airlock.projection import DEFAULT_POLICY_DIR, load_declarations

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_DPDP_ROWS = set(range(1, 11))


def test_every_rule_file_has_a_unique_rule_id_and_reads_resource_type():
    decl = load_declarations()
    assert len(decl) >= 14
    for rule_id, fields in decl.items():
        if rule_id == "dpdp.rule15_region":  # visibility flag: applies to any resource type
            continue
        assert "resource_type" in fields, "{} must test input.resource.resource_type".format(rule_id)
        assert fields, rule_id


def test_library_prefixes_match_folders():
    for path in sorted(DEFAULT_POLICY_DIR.rglob("*.rego")):
        if path.name.endswith("_test.rego"):
            continue
        rule_id = re.search(r"^#\s*rule_id:\s*(\S+)", path.read_text(encoding="utf-8"), re.M).group(1)
        expected = "dpdp." if path.parent.name == "dpdp" else "cis."
        assert rule_id.startswith(expected), "{} in {}".format(rule_id, path.parent.name)


def test_every_dpdp_mapping_row_has_a_rule():
    rows = set()
    for path in (DEFAULT_POLICY_DIR / "dpdp").glob("*.rego"):
        if path.name.endswith("_test.rego"):
            continue
        m = re.search(r"^#\s*mapping_row:\s*(\d+)", path.read_text(encoding="utf-8"), re.M)
        assert m, "{} is missing a '# mapping_row:' header".format(path.name)
        rows.add(int(m.group(1)))
    assert rows == EXPECTED_DPDP_ROWS


def test_every_mutator_rule_id_has_a_rego_rule():
    mutators_py = REPO_ROOT / "ml" / "mutation_engine" / "mutators.py"
    if not mutators_py.exists():
        return
    ids = set(re.findall(r'rule_id="([^"]+)"', mutators_py.read_text(encoding="utf-8")))
    assert ids, "no mutator rule ids found"
    assert ids <= set(load_declarations()), "mutator rule ids with no Rego rule: {}".format(
        sorted(ids - set(load_declarations()))
    )
