"""W-3 step 1 (design 2.2): the scanner exemption for the oracle neutral shape."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from supwngo.core import success_oracle

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "audit_target_values.py"
BASELINE = REPO_ROOT / "tests" / "data" / "target_values_baseline.json"

_spec = importlib.util.spec_from_file_location("audit_target_values_w3", SCRIPT)
audit = importlib.util.module_from_spec(_spec)
sys.modules["audit_target_values_w3"] = audit
_spec.loader.exec_module(audit)  # type: ignore[union-attr]

ORACLE_PATH = "supwngo/core/success_oracle.py"
W0_FROZEN_FIELDS_SHA256 = (
    "add1127b2361592c33c2f10de54103d99898d071cc7862bb4009b25bfaf302e1"
)


def _scan(src: str, path: str = ORACLE_PATH):
    return audit.scan_source(src, path)


def _c(hits):
    return [h for h in hits if h.cls == "C"]


def test_scanner_version_is_2():
    assert audit.SCANNER_VERSION == 2


def test_scanner_literal_equals_imported_constant():
    assert audit.ORACLE_NEUTRAL_SHAPE == success_oracle.NEUTRAL_FLAG_SHAPE
    assert audit.ORACLE_MODULE_PATH == ORACLE_PATH
    assert audit.ORACLE_SYMBOL == "NEUTRAL_FLAG_SHAPE"


def test_scanner_exempts_oracle_constant():
    const = success_oracle.NEUTRAL_FLAG_SHAPE
    src = f"NEUTRAL_FLAG_SHAPE = {const!r}\n"
    assert _c(_scan(src)) == []
    # Annotated assignment is the same binding.
    assert _c(_scan(f"NEUTRAL_FLAG_SHAPE: str = {const!r}\n")) == []


def test_exemption_is_exact_not_general():
    const = success_oracle.NEUTRAL_FLAG_SHAPE
    # Same literal, same symbol, wrong module: still a class-C hit.
    assert _c(_scan(f"NEUTRAL_FLAG_SHAPE = {const!r}\n", "supwngo/exploit/x.py"))
    # Right module, wrong symbol.
    assert _c(_scan(f"OTHER = {const!r}\n"))
    # Right module and symbol, but a different literal.
    assert _c(_scan("NEUTRAL_FLAG_SHAPE = r'(htb)\\{[^}]+\\}'\n"))
    # Right module, another occurrence of the exact pattern elsewhere.
    assert _c(_scan(f"NEUTRAL_FLAG_SHAPE = {const!r}\nCOPY = {const!r}\n"))
    assert _c(_scan(f"NEUTRAL_FLAG_SHAPE = {const!r}\nf(re.search({const!r}, out))\n"))
    # Tuple assignment is not the canonical binding.
    assert _c(_scan(f"NEUTRAL_FLAG_SHAPE, B = {const!r}, 1\n"))


def test_real_oracle_module_has_no_class_c_hit():
    src = (REPO_ROOT / ORACLE_PATH).read_text()
    assert _c(_scan(src)) == []


def test_baseline_frozen_set_unchanged():
    baseline = json.loads(BASELINE.read_text())
    rows = [
        (e["id"], e["path"], e["line"], e["class"], e["kind"], e["anchor"])
        for e in baseline["entries"]
    ]
    assert len(rows) == 157
    digest = hashlib.sha256(
        json.dumps(rows, separators=(",", ":")).encode()
    ).hexdigest()
    assert digest == W0_FROZEN_FIELDS_SHA256
    assert [e["id"] for e in baseline["entries"]] == [f"W-{i:04d}" for i in range(1, 158)]
    # The scanner-version field is metadata, not a frozen entry field.
    assert baseline["scanner_version"] == 1
    assert "scanner_version" not in {"id", "path", "line", "class", "kind", "anchor"}
