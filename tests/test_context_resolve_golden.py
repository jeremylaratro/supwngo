"""C9: byte-pinned regression vectors for :mod:`supwngo.schema.resolve`.

These vectors were captured by running the CURRENT (pre-unit-1) code, before
any change in this unit landed -- see
``docs/plans/2026-09-24-schema-unit-1-canonicalisation.md`` §8 item 9. They
are **regression evidence that these particular bytes have not moved**, not
proof of anything universal: a finite list of examples can show that a byte
string changed, it can never show that no byte string anywhere could change.
The universal half of C9 is carried elsewhere -- by C1's injectivity property
and by the purity property below (C3(i)), both of which quantify over a
*generated* domain rather than a fixed list.

**"Retained"**, precisely: this unit closes the canonicalisation domain (it
was accepting values -- enum, ``IntEnum``/``StrEnum``, tuple, set, dataclass,
every builtin subclass -- that it should never have accepted, because they
collided with unrelated JSON-native values). The retained set is the
**intersection** of what the pre-change domain accepted with what the
post-change domain accepts. Every vector below is drawn from that
intersection on purpose, so every one of them is expected to stay
byte-identical forever (or until a deliberate schema-version bump). A value
the new domain **refuses** -- an enum, a tuple, a raw set, a dataclass at an
open (evidence) position -- was never a legitimate member of the retained
set, and deliberately has **no vector here**: refusing it is the change this
unit makes, not a regression.

If a vector below ever changes, the schema version must change with it, and
a migration note must ship in the same commit -- this file existing and
staying green is the whole point of C9.
"""

from __future__ import annotations

import hashlib
import itertools

from supwngo.schema import resolve as R


def _raw(value=72, provenance=R.Provenance.MEASURED, identity="t_main",
         scope=R.Scope.BUILD, conditions=(), method="m1", by="supwngo offset",
         at="t1", key="stack.return_offset", binding=None, derived_from=(),
         evidence=None):
    obs = {"at": at}
    if evidence is not None:
        obs["evidence"] = evidence
    return {
        "key": key, "value": value, "provenance": provenance,
        "applies_to": {"identity": identity, "scope": scope,
                       "conditions": dict(conditions), "binding": binding},
        "method": method, "by": by, "derived_from": list(derived_from),
        "observations": [obs],
    }


# ---------------------------------------------------------------------------
# canonical() bytes, derive_id(), candidate_digest()
# ---------------------------------------------------------------------------


def test_golden_candidate1_canonical_bytes():
    """A plain int-valued, build-scoped candidate -- the simplest shape."""
    c = R.validate_candidate(_raw())
    assert R.canonical(c.project(R.CONTENT_FIELDS)) == (
        '{"applies_to":{"binding":null,"conditions":[],"identity":"t_main",'
        '"scope":"build"},"by":"supwngo offset","derived_from":[],'
        '"key":"stack.return_offset","method":"m1","provenance":"measured",'
        '"value":72}'
    )
    assert R.canonical(c.project(R.ID_DIGEST_FIELDS)) == (
        '{"applies_to":{"binding":null,"conditions":[],"identity":"t_main",'
        '"scope":"build"},"by":"supwngo offset","derived_from":[],'
        '"generation":0,"key":"stack.return_offset","method":"m1",'
        '"provenance":"measured","value":72}'
    )
    assert R.canonical(c.project(R.DEP_DIGEST_FIELDS)) == (
        '{"applies_to":{"binding":null,"conditions":[],"identity":"t_main",'
        '"scope":"build"},"by":"supwngo offset","derived_from":[],'
        '"generation":0,"id":"f_061afc3e10c1433e7ee898a23f8258b2",'
        '"key":"stack.return_offset","method":"m1","provenance":"measured",'
        '"value":72}'
    )


def test_golden_candidate1_id_and_digests():
    c = R.validate_candidate(_raw())
    assert c.id == "f_061afc3e10c1433e7ee898a23f8258b2"
    assert R.candidate_digest(c) == (
        "18cccb4f8f5a2d25cdb17ae98d563e299fa08695f2216c7f1a4c01ff7a117e06"
    )
    assert c.observations[0].digest() == (
        "58e08a65adfb30f215f0d66a72e59a7b24a5fcf9c36ea1963fda84c626dbe1e0"
    )


def test_golden_candidate2_with_mixed_evidence():
    """A LIBC_FILE-scoped, ASSERTED candidate with a non-identity applies_to
    and evidence covering every JSON-native open-domain type at once: str,
    int, bool, None, bytes."""
    c = R.validate_candidate(_raw(
        value=80, provenance=R.Provenance.ASSERTED, identity=None,
        scope=R.Scope.LIBC_FILE,
        conditions={"fd": "0", "input_method": "stdin"},
        method="m2", by="op2", at="t2", key="libc.system_offset",
        evidence={"tool": "objdump", "n": 3, "ok": True, "tag": None,
                  "blob": b"\x00\x01\xff"},
    ))
    assert R.canonical(c.project(R.CONTENT_FIELDS)) == (
        '{"applies_to":{"binding":null,"conditions":[["fd","0"],'
        '["input_method","stdin"]],"identity":null,"scope":"libc_file"},'
        '"by":"op2","derived_from":[],"key":"libc.system_offset",'
        '"method":"m2","provenance":"asserted","value":80}'
    )
    assert c.id == "f_358da8e00ae96dfcdd513fc20de9a838"
    assert R.candidate_digest(c) == (
        "18ee305fa4b0b4c35ea71736b17ce684805c1b80db3eef09f5c1fa2eed7615a1"
    )
    assert c.observations[0].digest() == (
        "29d0df95945c42c3d49800ae3c9d6826fa172f681e85578fc7d6b736a7e380df"
    )
    assert R.canonical(c.observations[0]) == (
        '{"at":"t2","evidence":[["blob",{"__bytes_b64__":"AAH/"}],'
        '["n",3],["ok",true],["tag",null],["tool","objdump"]]}'
    )


# ---------------------------------------------------------------------------
# Log endpoint ids -- PinRecord.id, resolve.py:1613 (rev-6 plan line number)
# ---------------------------------------------------------------------------


def test_golden_pin_record_id():
    c = R.validate_candidate(_raw())
    rec = R.PinRecord(cls="pin", key="stack.return_offset", candidate_id=c.id,
                      at="t1", seq=1, actor="op", reason="chosen")
    assert rec.id == "ca62f75f29808cd988d4d672851cd210"
    assert R.canonical(rec) == (
        '{"actor":"op","at":"t1","by_candidate_id":null,'
        f'"candidate_id":"{c.id}","cls":"pin","key":"stack.return_offset",'
        '"reason":"chosen","seq":1}'
    )


# ---------------------------------------------------------------------------
# canonical_document() for a small built store
# ---------------------------------------------------------------------------


def test_golden_canonical_document_small_store_PRE_V2_RECORD():
    """**PRE-V2 HISTORICAL RECORD -- not a live call into resolve.py.**

    This is the exact byte string ``canonical_document()`` produced for the
    fixture below under schema ``supwngo.context/v1``, captured before F7's
    fix bumped the version. It is a literal frozen string, not derived by
    calling the runtime, because ``canonical_document()`` now always emits
    ``supwngo.context/v2`` -- there is no longer any way to ask it for v1
    bytes. Retained here, byte for byte, because C9 requires a vector that
    changes to be replaced by a version bump plus a migration note, not
    silently overwritten; see CHANGELOG.md for the migration note. The live
    equivalent under v2 is :func:`test_golden_canonical_document_small_store`
    immediately below -- identical byte for byte except the trailing
    ``schema_version``.
    """
    doc_v1 = (
        '{"conflicts":[{"candidate_ids":["f_061afc3e10c1433e7ee898a23f8258b2",'
        '"f_fa0ac41b17534efea05c7ec4a175507e"],"cls":"equally_specific",'
        '"key":"stack.return_offset"}],"facts":{"libc.system_offset":'
        '[{"applies_to":{"binding":null,"conditions":[],"identity":null,'
        '"scope":"libc_file"},"by":"supwngo offset","derived_from":[],'
        '"generation":0,"id":"f_5578f75b99bbacf9c8a9e8e13698d5b4",'
        '"key":"libc.system_offset","method":"m3","observations":'
        '[{"at":"t1","evidence":[]}],"provenance":"measured","state":"active",'
        '"value":4096}],"stack.return_offset":[{"applies_to":{"binding":null,'
        '"conditions":[],"identity":"t_main","scope":"build"},'
        '"by":"supwngo offset","derived_from":[],"generation":0,'
        '"id":"f_061afc3e10c1433e7ee898a23f8258b2",'
        '"key":"stack.return_offset","method":"m1","observations":'
        '[{"at":"t1","evidence":[]}],"provenance":"measured","state":"active",'
        '"value":72},{"applies_to":{"binding":null,"conditions":[],'
        '"identity":"t_main","scope":"build"},"by":"supwngo offset",'
        '"derived_from":[],"generation":0,'
        '"id":"f_fa0ac41b17534efea05c7ec4a175507e",'
        '"key":"stack.return_offset","method":"m2","observations":'
        '[{"at":"t1","evidence":[]}],"provenance":"measured","state":"active",'
        '"value":80}]},"resolutions":[{"actor":"op","at":"t3",'
        '"by_candidate_id":null,'
        '"candidate_id":"f_061afc3e10c1433e7ee898a23f8258b2","cls":"pin",'
        '"key":"stack.return_offset","reason":"operator chose it","seq":1}],'
        '"schema_version":"supwngo.context/v1"}'
    )
    assert hashlib.sha256(doc_v1.encode("utf-8")).hexdigest() == (
        "b4b79839ed70096dff4d71f30d7f2a4eddc864eaf620877bb655fbccc1b7e9fe"
    )


def test_golden_canonical_document_small_store():
    """The v2 live equivalent of the pre-v2 record above (F7): same fixture,
    same bytes except the trailing ``schema_version``, captured by actually
    calling ``canonical_document()`` post-bump."""
    s = R.FactStore()
    R.merge(s, _raw())
    R.merge(s, _raw(value=80, method="m2"))
    R.merge(s, _raw(value=0x1000, key="libc.system_offset",
                    scope=R.Scope.LIBC_FILE, identity=None, method="m3"))
    a, _b = s.candidates("stack.return_offset")
    R.pin(s, "stack.return_offset", a.id, "t3", "operator chose it", "op")
    doc = R.canonical_document(s)
    assert doc == (
        '{"conflicts":[{"candidate_ids":["f_061afc3e10c1433e7ee898a23f8258b2",'
        '"f_fa0ac41b17534efea05c7ec4a175507e"],"cls":"equally_specific",'
        '"key":"stack.return_offset"}],"facts":{"libc.system_offset":'
        '[{"applies_to":{"binding":null,"conditions":[],"identity":null,'
        '"scope":"libc_file"},"by":"supwngo offset","derived_from":[],'
        '"generation":0,"id":"f_5578f75b99bbacf9c8a9e8e13698d5b4",'
        '"key":"libc.system_offset","method":"m3","observations":'
        '[{"at":"t1","evidence":[]}],"provenance":"measured","state":"active",'
        '"value":4096}],"stack.return_offset":[{"applies_to":{"binding":null,'
        '"conditions":[],"identity":"t_main","scope":"build"},'
        '"by":"supwngo offset","derived_from":[],"generation":0,'
        '"id":"f_061afc3e10c1433e7ee898a23f8258b2",'
        '"key":"stack.return_offset","method":"m1","observations":'
        '[{"at":"t1","evidence":[]}],"provenance":"measured","state":"active",'
        '"value":72},{"applies_to":{"binding":null,"conditions":[],'
        '"identity":"t_main","scope":"build"},"by":"supwngo offset",'
        '"derived_from":[],"generation":0,'
        '"id":"f_fa0ac41b17534efea05c7ec4a175507e",'
        '"key":"stack.return_offset","method":"m2","observations":'
        '[{"at":"t1","evidence":[]}],"provenance":"measured","state":"active",'
        '"value":80}]},"resolutions":[{"actor":"op","at":"t3",'
        '"by_candidate_id":null,'
        '"candidate_id":"f_061afc3e10c1433e7ee898a23f8258b2","cls":"pin",'
        '"key":"stack.return_offset","reason":"operator chose it","seq":1}],'
        '"schema_version":"supwngo.context/v2"}'
    )
    assert hashlib.sha256(doc.encode("utf-8")).hexdigest() == (
        "5012c11b6bf95e9889b776b715fd6c5af3e6ef215eb0cbaac37858b2bc3f364c"
    )


# ---------------------------------------------------------------------------
# C3(i): canonical() is pure -- independent of call order, repetition, and
# interleaving.  This is a PROPERTY over a generated domain, not a vector: it
# is the universal half of C3 that a finite list of examples cannot carry.
# ---------------------------------------------------------------------------


#: Leaves for the GENERATED purity domain below: the RETAINED
#: (root-admissible) types this unit's vectors above also use -- None,
#: bool, int, str, and bytes (tagged). No tuple/set/frozenset/Enum: those
#: are refused at canonical()'s root (F1) and have no vector here for the
#: same reason the module docstring gives.
_LEAVES = (None, True, False, 0, 1, -5, "", "a", "b64:eA==", b"", b"x", b"\xff\x00")

#: A reduced leaf set for the two itertools.product steps in
#: _purity_domain: one of the three purity tests below runs
#: itertools.product(domain, domain), so this generator's own fan-out
#: directly controls that test's O(N**2) host load -- kept small on
#: purpose, not because a bigger set would be wrong.
_PAIR_LEAVES = (None, True, 0, 1, "", "a", b"", b"x")


def _purity_domain():
    """A GENERATED set of legal, retained-domain values -- built by
    recursive/product construction, not a hand-written list (F4). C3(i) is
    a UNIVERSAL claim ("canonical() is pure for every legal value"); a
    fixed list can only ever be a finite sample of that claim, and can miss
    exactly the one combination (an unlisted legal nesting, say) that a
    call-history bug shows on and nothing else does. Two levels of
    genuine nesting: depth 1 pairs every leaf in _PAIR_LEAVES against
    every other one, via itertools.product rather than being enumerated by
    hand; depth 2 nests a deterministic stride of what depth 1 just
    produced one level further, so the GENERATOR decides what depth 2
    covers, not a hand-picked subset of it.
    """
    domain = list(_LEAVES)
    pairs = list(itertools.product(_PAIR_LEAVES, repeat=2))
    domain.extend([a, b] for a, b in pairs)
    domain.extend({"a": a, "b": b} for a, b in pairs)
    for v in domain[len(_LEAVES)::16]:
        domain.append([v])
        domain.append({"n": v})
    return domain


def test_purity_repeated_calls_agree():
    """Repeated calls to canonical() on the SAME value, back to back, must
    produce byte-identical output every time."""
    for value in _purity_domain():
        first = R.canonical(value)
        for _ in range(5):
            assert R.canonical(value) == first, (
                f"canonical({value!r}) is not stable across repeated calls"
            )


def test_purity_interleaved_calls_agree():
    """Interleaving calls to canonical() over DIFFERENT values must not let
    one call's result depend on which other calls came before it -- canonical
    must carry no cross-call state."""
    domain = _purity_domain()
    expected = {id(v): R.canonical(v) for v in domain}
    # Call in every pairwise interleaving, plus full round-robin passes.
    for a, b in itertools.product(domain, domain):
        assert R.canonical(a) == expected[id(a)]
        assert R.canonical(b) == expected[id(b)]
    for _ in range(3):
        for v in domain:
            assert R.canonical(v) == expected[id(v)]
        for v in reversed(domain):
            assert R.canonical(v) == expected[id(v)]


def test_purity_independent_of_call_order():
    """The byte string canonical() returns for a value must not depend on
    what order a batch of values was canonicalised in."""
    domain = _purity_domain()
    forward = [R.canonical(v) for v in domain]
    backward = [R.canonical(v) for v in reversed(domain)]
    assert forward == list(reversed(backward)), (
        "canonical() results depend on the order values were canonicalised in"
    )
