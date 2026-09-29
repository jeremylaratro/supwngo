"""Tests for the data-only indexed-read exfiltration executor."""

from supwngo.exploit.pipeline.executors.oob_read_techniques import (
    OobIndexReadExfilExecutor,
    reassemble_index_values,
)


def test_reassembles_signed_printed_ints_at_all_required_widths():
    values = [(8, 0x47414C46), (9, 0x7B)]

    blobs = reassemble_index_values(values)

    assert blobs[4].startswith(b"FLAG{")
    assert len(blobs[8]) == 16
    assert blobs[1] == b"F{" 


def test_executor_has_late_stable_name():
    from supwngo.exploit.pipeline.orchestrator import (
        FIRST_TECHNIQUES,
        LAST_TECHNIQUES,
    )

    assert OobIndexReadExfilExecutor.name == "oob_index_read_exfil"
    assert "oob_index_read_exfil" not in FIRST_TECHNIQUES
    assert LAST_TECHNIQUES[0] == "oob_index_read_exfil"
