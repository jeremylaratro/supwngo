"""
Validation gates for `DeliverySpec.build_argv()` (contracts.py).

Background: a peer review reproduced five ways `build_argv()` silently
accepted an undeliverable or contradictory spec instead of raising --
worst of all, an unrecognized/typoed `sink` fell through every branch and
was silently treated as stdin, DROPPING the payload with no error at all.
This file gates the five fixes, one rule at a time, each paired with a
non-raising control so no test can pass vacuously.

Scope: this file tests ONLY `DeliverySpec.build_argv()`'s validation. It
does not touch `analysis/vector_probe.py` or its own test files -- those
are owned separately (see test_input_vector_foundation.py /
test_input_vector_fixture_validation.py).
"""
from __future__ import annotations

import pytest

from supwngo.exploit.pipeline.contracts import (
    DeliverySpec,
    SINK_ARGV,
    SINK_FILE_ARGV,
    SINK_FILE_FIXED,
    SINK_STDIN,
)


# ---------------------------------------------------------------------------
# Load-bearing invariant: the default spec must never raise and must
# reproduce today's argv byte-for-byte at every existing spawn site.
# ---------------------------------------------------------------------------

class TestDefaultInstanceInvariant:
    def test_default_spec_never_raises_and_yields_binary_path_only(self):
        spec = DeliverySpec()
        assert spec.sink == SINK_STDIN
        assert spec.argv_template == ()
        assert spec.build_argv("/bin/x") == ["/bin/x"]

    def test_default_spec_never_raises_even_with_a_payload_value_supplied(self):
        assert DeliverySpec().build_argv("/bin/x", "/tmp/payload.bin") == ["/bin/x"]


# ---------------------------------------------------------------------------
# Rule 1: unknown/unrecognized sink -> raise, naming the four valid values.
# ---------------------------------------------------------------------------

class TestRule1UnknownSink:
    def test_typoed_sink_raises(self):
        spec = DeliverySpec(sink="file-arg", payload_filename="p.bin")
        with pytest.raises(ValueError, match="SINK_STDIN|SINK_ARGV|SINK_FILE_ARGV|SINK_FILE_FIXED"):
            spec.build_argv("/v")

    def test_a_recognized_sink_with_an_otherwise_valid_spec_does_not_raise(self):
        """Paired control: a real sink (SINK_STDIN, no template) must not
        raise -- proves the gate is keyed on recognizing the sink value,
        not on rejecting every DeliverySpec."""
        spec = DeliverySpec(sink=SINK_STDIN)
        assert spec.build_argv("/v") == ["/v"]


# ---------------------------------------------------------------------------
# Rule 2: a file sink whose template has a {payload_file}/@@ token but an
# empty payload_value -> raise.
# ---------------------------------------------------------------------------

class TestRule2EmptyPayloadValueForFileToken:
    def test_file_argv_with_default_empty_payload_value_raises(self):
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
                             payload_filename="p.bin")
        with pytest.raises(ValueError, match="payload_value"):
            spec.build_argv("/v")

    def test_file_argv_with_a_real_payload_value_does_not_raise(self):
        """Paired control: the same spec with a non-empty payload_value
        must substitute normally, not raise."""
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
                             payload_filename="p.bin")
        assert spec.build_argv("/v", "/tmp/p") == ["/v", "/tmp/p"]


# ---------------------------------------------------------------------------
# Rule 3: {payload_arg} present when sink is anything other than SINK_ARGV
# -> raise.
# ---------------------------------------------------------------------------

class TestRule3PayloadArgWrongSink:
    def test_payload_arg_token_with_file_fixed_sink_raises(self):
        spec = DeliverySpec(SINK_FILE_FIXED, ("{payload_arg}",), "d.cfg")
        with pytest.raises(ValueError, match="payload_arg"):
            spec.build_argv("/v", "VAL")

    def test_payload_arg_token_with_argv_sink_does_not_raise(self):
        """Paired control: the same token is exactly what SINK_ARGV
        expects and must not raise."""
        spec = DeliverySpec(sink=SINK_ARGV, argv_template=("{payload_arg}",))
        assert spec.build_argv("/v", "VAL") == ["/v", "VAL"]


# ---------------------------------------------------------------------------
# Rule 4: {payload_file}/@@ present when sink is SINK_STDIN or SINK_ARGV
# -> raise.
# ---------------------------------------------------------------------------

class TestRule4PayloadFileWrongSink:
    def test_payload_file_token_with_stdin_sink_raises(self):
        spec = DeliverySpec(SINK_STDIN, ("{payload_file}",))
        with pytest.raises(ValueError, match="payload_file"):
            spec.build_argv("/v", "/tmp/p")

    def test_payload_arg_token_with_argv_sink_still_does_not_raise(self):
        """Paired control distinguishing this from rule 3's control:
        SINK_ARGV with the CORRECT placeholder ({payload_arg}) must not
        raise -- proves the gate targets {payload_file} specifically for
        SINK_ARGV, not SINK_ARGV in general."""
        spec = DeliverySpec(sink=SINK_ARGV, argv_template=("{payload_arg}",))
        assert spec.build_argv("/v", "VAL") == ["/v", "VAL"]

    def test_stdin_with_a_plain_non_placeholder_template_does_not_raise(self):
        """Paired control (explicitly required): stdin delivery and an
        argv template are orthogonal -- a plain flag must substitute
        normally, not raise, distinguishing "stdin + {payload_file}" from
        "stdin + any template"."""
        spec = DeliverySpec(sink=SINK_STDIN, argv_template=("--config", "static.cfg"))
        assert spec.build_argv("/v", "/tmp/p") == ["/v", "--config", "static.cfg"]


# ---------------------------------------------------------------------------
# Rule 5: both placeholder kinds present in one template -> raise.
# ---------------------------------------------------------------------------

class TestRule5BothPlaceholderKindsPresent:
    def test_both_tokens_in_one_template_raises(self):
        """Match on wording unique to the dedicated "both placeholder
        kinds" gate ("two distinct placeholder kinds"), not merely on the
        substrings "payload_file"/"payload_arg" -- those also appear
        (via the repr of argv_template) in rule 3's message, which would
        make this assertion pass even if the rule-5-specific gate were
        disabled and rule 3 caught the case instead. Proven by disabling
        the rule-5 gate during red-proofing: this exact regex failed to
        match while a looser one incorrectly kept passing."""
        spec = DeliverySpec(SINK_FILE_ARGV, ("{payload_file}", "{payload_arg}"), "p.bin")
        with pytest.raises(ValueError, match="two distinct placeholder kinds"):
            spec.build_argv("/v", "/tmp/p")

    def test_only_the_file_token_alone_does_not_raise(self):
        """Paired control: the same sink/filename with only the ONE token
        it actually needs must not raise -- proves the gate fires on
        "both present", not on the presence of {payload_file} alone."""
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
                             payload_filename="p.bin")
        assert spec.build_argv("/v", "/tmp/p") == ["/v", "/tmp/p"]
