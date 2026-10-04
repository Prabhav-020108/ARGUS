"""
ARGUS Phase 4 - leak-check, the hard backstop.

    leak_check(payload, vault_values) -> {"vault_hits": 0, "secret_hits": 0, "pii_hits": 0}
    raises LeakDetected if anything is found.

Run on the FINAL outbound payload, right before it is handed to any generator. It exists to
catch bugs in projection / tokenization / scrubbing, not to replace them.

What it looks for, in every string of the payload (dict keys included):
  * any real value held in the vault for this record (whole-word, case-insensitive),
  * any secret or personal-data pattern (the same detectors the scrubber uses),
  * the same checks again on base64-decoded versions of base64-looking chunks,
  * the same checks again on sibling strings joined together (catches a secret split across fields).
The exception message contains counts only, never the matched text.
"""

import base64
import binascii
import re

from privacy.scrubbers.scrubbers import detect

_B64_CHUNK_RE = re.compile(r"[A-Za-z0-9+/_\-]{12,}={0,2}")
_JOINED_MIN_LEN = 8


class LeakDetected(Exception):
    def __init__(self, summary):
        self.summary = summary
        super().__init__(
            "leak-check blocked the payload: {vault_hits} vault value(s), "
            "{secret_hits} secret hit(s), {pii_hits} personal-data hit(s)".format(**summary)
        )


def _leaves(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                yield k
            yield from _leaves(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _leaves(v)
    elif isinstance(node, str):
        yield node
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        yield str(node)


def _sibling_joins(node):
    """For every dict/list, the direct string children joined with no separator (catches a value
    split across sibling fields or list items). Dict keys are excluded so word boundaries hold."""
    if isinstance(node, dict):
        children = list(node.values())
    elif isinstance(node, (list, tuple)):
        children = list(node)
    else:
        return
    texts = [c for c in children if isinstance(c, str)]
    if len(texts) > 1:
        yield "".join(texts)
    for c in children:
        yield from _sibling_joins(c)


def _value_leaves(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from _value_leaves(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _value_leaves(v)
    elif isinstance(node, str):
        yield node
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        yield str(node)


def _looks_like_text(data):
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) >= 0.9


def _decoded_variants(text):
    out = []
    for chunk in _B64_CHUNK_RE.findall(text):
        padded = chunk.rstrip("=")
        padded += "=" * (-len(padded) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(padded)
            except (binascii.Error, ValueError):
                continue
            if _looks_like_text(raw):
                out.append(raw.decode("utf-8", errors="ignore"))
    return out


def _vault_value_regexes(vault_values):
    regexes = []
    for v in vault_values:
        if v:
            regexes.append(
                (len(v), re.compile(r"(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])", re.IGNORECASE), v.lower())
            )
    return regexes


def leak_check(payload, vault_values=()):
    leaves = list(_leaves(payload))
    joined_views = list(_sibling_joins(payload))
    joined_views.append("".join(_value_leaves(payload)))
    views = list(leaves)
    views.extend(joined_views)
    views.append(" ".join(leaves))
    for text in leaves + joined_views:
        views.extend(_decoded_variants(text))

    vault_rx = _vault_value_regexes(vault_values)
    vault_hits = secret_hits = pii_hits = 0

    for value_len, rx, lowered in vault_rx:
        found = any(rx.search(view) for view in views)
        if not found and value_len >= _JOINED_MIN_LEN:
            found = any(lowered in j.lower() for j in joined_views)  # value split across fields
        if found:
            vault_hits += 1

    for view in views:
        for hit in detect(view):
            if hit.kind == "secret":
                secret_hits += 1
            else:
                pii_hits += 1

    summary = {"vault_hits": vault_hits, "secret_hits": secret_hits, "pii_hits": pii_hits}
    if vault_hits or secret_hits or pii_hits:
        raise LeakDetected(summary)
    return summary
