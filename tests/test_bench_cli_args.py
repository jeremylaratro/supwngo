"""
Gates for the M-1b ingress corpus and the one shared-harness change it needed.

Two things are protected here, and they are different kinds of claim:

1. **The `cli_args:` manifest key must be inert for every pre-existing corpus.**
   `run_bench.py` is what produces the M-1a baseline (13/13 eligible SUCCESS at
   5/5 reps), and that baseline is only comparable across runs if a manifest
   with no `cli_args:` key builds the identical argument list it built before
   the key existed. That is asserted, not assumed.

2. **The new manifest's declared vectors must be VALID before anything runs
   them.** Round-2 review of the M-1b plan found that eight planned rows omitted
   the mandatory `--input-name`; both file sinks raise on an empty
   `payload_filename` (`contracts.py`), so those rows would have been skipped as
   invalid configuration and the failure misattributed to the transport. These
   tests build a real `DeliverySpec` from each manifest row, so an invalid
   declaration fails here rather than silently degrading a benchmark result.

That second class is the point of the user's standing rule: validate a custom
assessment BEFORE running the tests that trust it.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

from supwngo.exploit.pipeline.contracts import (
    SINK_ARGV,
    SINK_FILE_ARGV,
    SINK_FILE_FIXED,
    SINK_STDIN,
    DeliverySpec,
    is_file_sink,
)

#: A stand-in binary path. `build_argv` never touches the filesystem -- it only
#: assembles argv -- so any path works and no target is spawned.
_BINPATH = "/bin/true"
_PAYLOAD_VALUE = "payload.bin"

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH = REPO_ROOT / "benchmark"

#: Manifests that existed before `cli_args:` and whose runs must not change.
PRE_EXISTING_MANIFESTS = ("corpus.yaml", "corpus_r2.yaml")
VECTORS_MANIFEST = BENCH / "corpus_vectors.yaml"


def _load_run_bench():
    """Import `benchmark/run_bench.py` by path -- it is a script, not a package
    module, so a plain import would not find it."""
    spec = importlib.util.spec_from_file_location(
        "bench_run_bench", BENCH / "run_bench.py"
    )
    mod = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec_module: run_bench defines frozen dataclasses, and
    # `dataclasses` resolves `cls.__module__` through `sys.modules` while
    # processing them. Without this the import dies with
    # `AttributeError: 'NoneType' object has no attribute '__dict__'`.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


run_bench = _load_run_bench()


def _targets(manifest: Path) -> list[dict]:
    return yaml.safe_load(manifest.read_text())["targets"]


# --------------------------------------------------------------------------
# 1. The key is inert for pre-existing corpora
# --------------------------------------------------------------------------

class TestCliArgsDefaultsToEmpty:
    """A manifest without the key must produce exactly no extra arguments."""

    @pytest.mark.parametrize(
        "target",
        [{}, {"slug": "x"}, {"cli_args": None}, {"cli_args": []}],
        ids=["absent-entirely", "other-keys-only", "explicit-None", "explicit-empty"],
    )
    def test_absent_or_empty_yields_no_arguments(self, target):
        assert run_bench.target_cli_args(target) == []

    def test_a_declared_list_is_passed_through_in_order_as_strings(self):
        # Order matters: `--input-argv "-f {payload_file}"` is whitespace-split
        # downstream, so a reordering silently changes the launch.
        target = {"cli_args": ["--input-vector", "file-argv", "--input-name", "p.bin"]}
        assert run_bench.target_cli_args(target) == [
            "--input-vector", "file-argv", "--input-name", "p.bin",
        ]

    @pytest.mark.parametrize("manifest_name", PRE_EXISTING_MANIFESTS)
    def test_no_pre_existing_target_declares_cli_args(self, manifest_name):
        """The guard on M-1a's comparability.

        If a target in one of these manifests ever gains `cli_args:`, that
        run's arguments change and the recorded baseline stops being a
        like-for-like comparison. Then this test should fail and the baseline
        should be re-measured -- not the assertion relaxed.
        """
        manifest = BENCH / manifest_name
        if not manifest.is_file():
            pytest.skip(f"{manifest_name} is not present in this checkout")
        offenders = [
            t["slug"] for t in _targets(manifest) if t.get("cli_args")
        ]
        assert offenders == [], (
            f"{manifest_name} targets now declare cli_args: {offenders}. "
            "The M-1a baseline was measured without them and is no longer "
            "comparable; re-measure it rather than deleting this assertion."
        )

    def test_the_guard_above_is_not_vacuous(self):
        """Positive control: the offender-detecting expression must be able to
        fire. An absence assertion whose subject never exists passes forever."""
        fake = [{"slug": "a"}, {"slug": "b", "cli_args": ["--input-vector", "argv"]}]
        offenders = [t["slug"] for t in fake if t.get("cli_args")]
        assert offenders == ["b"]


# --------------------------------------------------------------------------
# 2. Every declared vector in the new manifest is a VALID DeliverySpec
# --------------------------------------------------------------------------

def _spec_kwargs_from_cli_args(cli_args: list[str]) -> dict:
    """Translate a manifest `cli_args:` list into the DeliverySpec fields the
    CLI would build from it. Mirrors the CLI's own option names so a manifest
    that the CLI would reject is rejected here too."""
    out = {"sink": SINK_STDIN, "payload_filename": "", "argv_template": ()}
    i = 0
    while i < len(cli_args):
        tok = cli_args[i]
        if tok == "--input-vector":
            out["sink"] = cli_args[i + 1]; i += 2
        elif tok == "--input-name":
            out["payload_filename"] = cli_args[i + 1]; i += 2
        elif tok == "--input-argv":
            out["argv_template"] = tuple(cli_args[i + 1].split()); i += 2
        else:
            i += 1
    return out


VECTOR_TARGETS = _targets(VECTORS_MANIFEST) if VECTORS_MANIFEST.is_file() else []
VECTOR_IDS = [t["slug"] for t in VECTOR_TARGETS]


@pytest.mark.skipif(not VECTOR_TARGETS, reason="corpus_vectors.yaml absent")
class TestIngressManifestDeclaresValidSpecs:

    def test_the_manifest_is_non_empty_so_the_parametrization_is_not_vacuous(self):
        assert len(VECTOR_TARGETS) >= 6, VECTOR_IDS

    @pytest.mark.parametrize("target", VECTOR_TARGETS, ids=VECTOR_IDS)
    def test_each_target_builds_a_valid_argv(self, target):
        """`build_argv` -- NOT the constructor -- is where DeliverySpec's
        validation lives (`contracts.py:203`); the dataclass has no
        `__post_init__`. An earlier version of this test constructed the spec
        and asserted nothing, and the red-proofs below are what exposed it.

        Calling `build_argv` runs every gate, so an empty `payload_filename` on
        a file sink, or a `file-argv` template with no payload token, fails here
        rather than degrading a benchmark result into a transport failure.
        """
        spec = DeliverySpec(**_spec_kwargs_from_cli_args(
            run_bench.target_cli_args(target)))
        argv = spec.build_argv(_BINPATH, _PAYLOAD_VALUE)  # raises if invalid
        assert argv[0] == _BINPATH
        assert spec.sink in (SINK_STDIN, SINK_ARGV, SINK_FILE_ARGV, SINK_FILE_FIXED)

    @pytest.mark.parametrize("target", VECTOR_TARGETS, ids=VECTOR_IDS)
    def test_file_sinks_declare_a_payload_filename(self, target):
        spec = DeliverySpec(**_spec_kwargs_from_cli_args(
            run_bench.target_cli_args(target)))
        # module-level function, not a method on the spec
        if is_file_sink(spec.sink):
            assert spec.payload_filename, (
                f"{target['slug']} declares a file sink with no --input-name; "
                "both file sinks reject an empty payload_filename, so this row "
                "would be skipped as invalid rather than measured"
            )

    @pytest.mark.parametrize("target", VECTOR_TARGETS, ids=VECTOR_IDS)
    def test_a_file_argv_row_places_the_payload_path_in_argv(self, target):
        """The positive half: for a file-argv row the rendered argv must
        actually contain the payload path somewhere. A template that validates
        but drops the path would deliver a file nothing ever opens."""
        spec = DeliverySpec(**_spec_kwargs_from_cli_args(
            run_bench.target_cli_args(target)))
        if spec.sink != SINK_FILE_ARGV:
            pytest.skip(f"{target['slug']} is not a file-argv row")
        argv = spec.build_argv(_BINPATH, _PAYLOAD_VALUE)
        assert any(_PAYLOAD_VALUE in tok for tok in argv[1:]), argv

    # ---- red-proofs: mutate to WRONG-but-present and require a raise --------

    def test_an_empty_payload_filename_on_a_file_sink_raises(self):
        with pytest.raises(ValueError):
            DeliverySpec(
                sink=SINK_FILE_ARGV, payload_filename="",
                argv_template=("{payload_file}",),
            ).build_argv(_BINPATH, _PAYLOAD_VALUE)

    def test_a_file_argv_row_without_a_payload_token_raises(self):
        with pytest.raises(ValueError):
            DeliverySpec(
                sink=SINK_FILE_ARGV, payload_filename="p.bin",
                argv_template=("--no-token-here",),
            ).build_argv(_BINPATH, _PAYLOAD_VALUE)

    def test_a_payload_file_token_on_a_non_file_sink_raises(self):
        with pytest.raises(ValueError):
            DeliverySpec(
                sink=SINK_ARGV, payload_filename="",
                argv_template=("{payload_file}",),
            ).build_argv(_BINPATH, _PAYLOAD_VALUE)

    def test_every_declared_argv_template_carries_a_payload_token(self):
        """AFL's `@@` is a supported alias for `{payload_file}`
        (`_normalize_argv_template`), so both spellings count. Asserted over the
        whole manifest so a newly added row cannot slip in without one."""
        checked = 0
        for target in VECTOR_TARGETS:
            spec = DeliverySpec(**_spec_kwargs_from_cli_args(
                run_bench.target_cli_args(target)))
            if spec.sink == SINK_FILE_ARGV:
                joined = " ".join(spec.argv_template)
                assert "{payload_file}" in joined or "@@" in joined, target["slug"]
                checked += 1
        assert checked >= 4, f"only {checked} file-argv rows found; gate is thin"
