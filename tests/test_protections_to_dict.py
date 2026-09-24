"""Serialization contract for `DetailedProtections.to_dict()`.

`DetailedProtections` extends `Protections` with 14 fields but used to inherit
`Protections.to_dict()`, which hard-codes six keys -- so `supwngo analyze
--json` measured ten facts and then discarded them at serialization. These
tests pin the fix.

Read the docstrings before trusting any of this as evidence. Three tests fail
against the unfixed code and are the actual proof; two pass against it and are
labelled as regression locks, not proof. See
`docs/plans/2026-09-24-walkthrough-merge-and-protections-to-dict.md`.
"""

import dataclasses
import json

import pytest

from supwngo.analysis.protections import _UNMEASURED, DetailedProtections
from supwngo.core.binary import Protections


#: The exact wire schema. Written out by hand on purpose: the point of an
#: explicit serializer is that a reviewer can see its output in the diff, and
#: a test that only checks "nothing is missing" would wave through a typo
#: alias or a stale compatibility key.
EXPECTED_KEYS = {
    # inherited, already emitted before the fix
    "canary",
    "nx",
    "pie",
    "relro",
    "fortify",
    "aslr",
    # added by the fix -- each one is assigned by ProtectionAnalyzer.analyze()
    "full_relro",
    "partial_relro",
    "stack_protector",
    "fortify_level",
    "pie_type",
    "stripped",
    "static",
    "has_debug_info",
    "libc_version",
    "uses_tcache",
}

#: The six keys the base class emits, unchanged by this work.
BASE_KEYS = {"canary", "nx", "pie", "relro", "fortify", "aslr"}

ALL_FIELDS = [f.name for f in dataclasses.fields(DetailedProtections)]


# --------------------------------------------------------------------------
# These three fail against the unfixed code. They are the proof.
# --------------------------------------------------------------------------


def test_every_field_is_either_emitted_or_declared_unmeasured():
    """No field may silently vanish from the serialized form.

    Every declared field is either published by `to_dict()` or named in
    `_UNMEASURED` (because nothing ever measures it). A field in neither set
    is the original bug reappearing, so adding a field forces a deliberate
    choice instead of a silent omission.

    Against the unfixed `to_dict()` this fails with 10 unaccounted fields --
    the 16 absent keys less the 6 that `_UNMEASURED` legitimately absorbs, so
    10 is exactly the count of *measured* facts being discarded.
    """
    emitted = set(DetailedProtections().to_dict())
    unaccounted = [
        name for name in ALL_FIELDS if name not in emitted and name not in _UNMEASURED
    ]
    assert unaccounted == [], (
        f"{len(unaccounted)} field(s) are neither serialized nor declared "
        f"unmeasured, so analysis is being discarded: {unaccounted}"
    )


def test_emits_exactly_the_documented_key_set():
    """The wire schema is exactly `EXPECTED_KEYS` -- no more, no fewer.

    Asserting equality rather than containment is deliberate: a containment
    check passes while an extra key (a typo alias, a leaked derived value, a
    stale compatibility key) rides along unnoticed.

    Against the unfixed code this fails: only the 6 inherited keys appear.
    """
    assert set(DetailedProtections().to_dict()) == EXPECTED_KEYS


@pytest.mark.parametrize("field_name", sorted(EXPECTED_KEYS))
def test_each_field_reaches_its_own_key(field_name):
    """One-hot: each field must surface at its own key and nowhere else.

    The tempting shortcut -- set every boolean to True, assert every value is
    True -- cannot fail usefully. If `to_dict()` returned `"cfi": self.static`
    both would be True and the test would still pass. This project has shipped
    that defect before, so instead each field is perturbed *alone*, against an
    all-defaults baseline, and the resulting dict must differ at exactly that
    one key.

    Against the unfixed code all 16 parametrizations fail on the `missing`
    assertion, because the 10 added keys are absent from the dict entirely.
    """
    baseline = DetailedProtections().to_dict()
    probe = _perturb(field_name)
    changed = {k for k in baseline if baseline[k] != probe.get(k, baseline[k])}
    missing = EXPECTED_KEYS - set(probe)
    assert not missing, f"key(s) absent from to_dict(): {sorted(missing)}"
    assert changed == {field_name}, (
        f"perturbing {field_name!r} should change exactly that key; "
        f"changed={sorted(changed)}"
    )


def _perturb(field_name):
    """Serialize an instance in which only `field_name` differs from default."""
    default = getattr(DetailedProtections(), field_name)
    # bool before int: isinstance(True, int) is True.
    if isinstance(default, bool):
        value = not default
    elif isinstance(default, int):
        value = default + 7
    else:
        # Distinct per field so a cross-wired string cannot coincide.
        value = f"probe-{field_name}"
    return DetailedProtections(**{field_name: value}).to_dict()


# --------------------------------------------------------------------------
# These two PASS against the unfixed code. They are regression locks, and
# must not be counted as evidence that the bug was fixed.
# --------------------------------------------------------------------------


def test_values_are_json_native_and_round_trip():
    """Type-safety lock -- passes before the fix, so it proves nothing about it.

    `cli.py:124` serializes with `json.dump(..., default=str)` while the
    `cli.py:84` stdout path does not, so a non-native value would be
    stringified in the saved file and raise on stdout. Every value must be a
    JSON-native scalar and survive a round trip unchanged.
    """
    d = DetailedProtections().to_dict()
    for key, value in d.items():
        assert isinstance(value, (bool, int, str)) or value is None, (
            f"{key!r} is {type(value).__name__}, which json.dumps handles "
            f"inconsistently across the two analyze output paths"
        )
    assert json.loads(json.dumps(d)) == d


def test_base_protections_to_dict_is_unchanged():
    """Boundary lock -- passes before the fix, so it proves nothing about it.

    The fix is scoped to the subclass. The base serializer feeds
    `Binary.checksec()` and thus `StaticAnalyzer.analyze()["protections"]`;
    this pins it so the fix cannot leak into that path.
    """
    assert set(Protections().to_dict()) == BASE_KEYS


def test_unmeasured_set_names_only_real_never_assigned_fields():
    """`_UNMEASURED` must not become a dumping ground.

    Every name in it has to be a real field, so the escape hatch in the
    partition test cannot be satisfied by a typo.
    """
    assert _UNMEASURED <= set(ALL_FIELDS), (
        f"_UNMEASURED names non-existent field(s): "
        f"{sorted(_UNMEASURED - set(ALL_FIELDS))}"
    )
    assert not (_UNMEASURED & EXPECTED_KEYS), (
        "a field cannot be both published and declared unmeasured: "
        f"{sorted(_UNMEASURED & EXPECTED_KEYS)}"
    )
