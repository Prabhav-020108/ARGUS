"""
ARGUS Phase 4 - rule-scoped, default-deny attribute projection.

A finding is shown to a generator only through the fields that the TRIGGERING Rego rule
reads. The list of fields is not maintained by hand: it is derived from the rule's own
source (every `input.resource.<field>` reference), so the privacy boundary and the
compliance check always look at exactly the same fields. Anything not read by the rule
(tags, free-text names, descriptions, user_data ...) is dropped.

Convention every .rego rule file must follow (enforced by tests):
  * a header comment line   # rule_id: <id>
  * attributes read only as input.resource.<field>  (never input.resource["x"])
"""

import copy
import functools
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_DIR = REPO_ROOT / "policy"

_RULE_ID_RE = re.compile(r"^\s*#\s*rule_id:\s*(\S+)\s*$", re.MULTILINE)
_FIELD_RE = re.compile(r"\binput\.resource\.([A-Za-z_][A-Za-z0-9_]*)")


class UnknownRuleError(KeyError):
    """The rule id has no .rego file declaring it."""


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


@functools.lru_cache(maxsize=16)
def _load(policy_dir_str):
    declarations = {}
    for path in sorted(Path(policy_dir_str).rglob("*.rego")):
        if path.name.endswith("_test.rego"):
            continue
        text = path.read_text(encoding="utf-8")
        ids = _RULE_ID_RE.findall(text)
        if len(ids) != 1:
            raise ValueError(
                "{} must contain exactly one '# rule_id: <id>' header line (found {})".format(path.name, len(ids))
            )
        rule_id = ids[0]
        if rule_id in declarations:
            raise ValueError("Duplicate rule_id {!r} (in {})".format(rule_id, path.name))
        declarations[rule_id] = frozenset(_FIELD_RE.findall(_strip_comments(text)))
    return declarations


def clear_cache():
    _load.cache_clear()


def load_declarations(policy_dir=None):
    """{rule_id: frozenset of fields the rule reads}"""
    return _load(str(policy_dir or DEFAULT_POLICY_DIR))


def declared_fields(rule_id, policy_dir=None):
    decl = load_declarations(policy_dir)
    if rule_id not in decl:
        raise UnknownRuleError("No Rego rule declares rule_id {!r}".format(rule_id))
    return decl[rule_id]


def project(raw_finding, rule_id, policy_dir=None):
    """Return {"finding_id", "rule_id", "resource_id", "fields": {...}} (real values, not yet tokenized).

    raw_finding = {
        "finding_id": "F-0001",
        "resource_id": "<real id or name>",
        "resource_type": "AWSS3Bucket",
        "attributes": {<every property known about the resource>},
    }
    """
    allowed = declared_fields(rule_id, policy_dir)
    available = copy.deepcopy(dict(raw_finding.get("attributes") or {}))
    if raw_finding.get("resource_type") is not None:
        available["resource_type"] = raw_finding["resource_type"]
    return {
        "finding_id": raw_finding["finding_id"],
        "rule_id": rule_id,
        "resource_id": raw_finding["resource_id"],
        "fields": {f: available[f] for f in sorted(allowed) if f in available},
    }
