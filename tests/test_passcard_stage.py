"""Tests for benchmark/passcard_stage.py (SP-01 plan sections 3.3 and 8.1 V-1).

The closure tests build a small challenge directory with gcc (a relative loader, a
two-level library chain, decoys no search path reaches). The S0 tests stage the
real binaries from the gitignored ``tests/htb-targets`` tree and skip without it.
"""

import hashlib
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from passcard_support import (  # noqa: E402
    BENCHMARK,
    REPO_ROOT,
    S0_SLUGS,
    TARGETS_ROOT,
    build_lib_tree,
    needs_gcc,
    needs_host_loader,
    needs_targets,
)

sys.path.insert(0, str(BENCHMARK))

import passcard_stage as st  # noqa: E402

DEP_CHAIN = ["ld/ld.so", "lib/libbar.so", "lib/libfoo.so"]
DECOYS = ["app.c", "app.debug", "notes.txt", "lib/libunused.so", "extra/libc.so.6"]


@pytest.fixture(scope="module")
def lib_tree(tmp_path_factory):
    # Only requested by tests marked needs_gcc/needs_host_loader, which skip first.
    return build_lib_tree(tmp_path_factory.mktemp("libtree"))


# --- paths -------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, bad",
    [
        ("/tmp/cell/tmp", False),
        ("/var/tmp/passcard-x/run-1/sick_rop-pwn-r1", False),
        ("/tmp/cell/.tmp", True),
        ("/tmp/.hidden/cell", True),
        ("/tmp/cell/../x", True),
        ("/tmp/a.b/c", False),  # a dot inside a component is fine
    ],
)
def test_dot_component_detection(path, bad):
    assert st.has_dot_component(path) is bad
    if bad:
        with pytest.raises(st.StageError, match="'.'-prefixed"):
            st.assert_no_dot_component(path)
    else:
        st.assert_no_dot_component(path)


# --- closure -----------------------------------------------------------------


@needs_gcc
@needs_host_loader
def test_closure_is_the_loader_and_the_resolved_library_chain(lib_tree):
    assert st.compute_closure(lib_tree, ["app"]) == DEP_CHAIN


@needs_gcc
@needs_host_loader
def test_a_library_next_to_the_loader_resolves_without_a_runpath(lib_tree):
    info = st.read_elf(lib_tree / "app2")
    assert info.runpath == () and info.rpath == ()
    assert st.compute_closure(lib_tree, ["app2"]) == ["ld/ld.so", "ld/libbar.so"]


@needs_gcc
@needs_host_loader
def test_the_host_libc_is_not_staged(lib_tree):
    # libc.so.6 is NEEDED by app but is not under the source dir on any search
    # path: extra/libc.so.6 is a decoy and must stay out.
    assert "libc.so.6" in st.read_elf(lib_tree / "app").needed
    assert not [p for p in st.compute_closure(lib_tree, ["app"]) if "libc" in p]


def test_a_non_elf_seed_has_no_dependencies(tmp_path):
    (tmp_path / "data.bin").write_bytes(b"MZ not an elf")
    assert st.compute_closure(tmp_path, ["data.bin"]) == []


def test_a_seed_that_escapes_the_source_directory_is_refused(tmp_path):
    with pytest.raises(st.StageError, match="escapes"):
        st.compute_closure(tmp_path, ["../x"])


# --- staging -----------------------------------------------------------------


@needs_gcc
@needs_host_loader
def test_the_cell_file_list_equals_the_computed_closure(lib_tree, tmp_path):
    cell = st.stage_cell(tmp_path, "app-pwn-r1", lib_tree, ["app"], ["flag.txt"])
    expected = sorted(["app", "flag.txt"] + DEP_CHAIN)
    assert cell.files == expected == st.staged_files(cell.path)
    assert cell.closure == DEP_CHAIN
    assert cell.placeholders == ["flag.txt"]
    assert cell.target == "app" and cell.target_path == cell.path / "app"
    assert cell.sha256 == hashlib.sha256((lib_tree / "app").read_bytes()).hexdigest()


@needs_gcc
@needs_host_loader
def test_unlisted_files_stay_out(lib_tree, tmp_path):
    cell = st.stage_cell(tmp_path, "c", lib_tree, ["app"])
    for decoy in DECOYS:
        assert not (cell.path / decoy).exists(), decoy
    assert not (cell.path / "app2").exists()


@needs_gcc
@needs_host_loader
def test_layout_has_private_tmp_home_and_cache(lib_tree, tmp_path):
    cell = st.stage_cell(tmp_path, "c", lib_tree, ["app"])
    for sub in ("tmp", "home", "cache"):
        assert (cell.path / sub).is_dir()
    assert st.CELL_SUBDIRS == ("tmp", "home", "cache")
    # Whatever the run later writes there is not part of the file list.
    (cell.path / "tmp" / "scratch").write_text("x")
    assert st.staged_files(cell.path) == cell.files


@needs_gcc
@needs_host_loader
def test_placeholder_content_is_neutral_and_not_flag_shaped(lib_tree, tmp_path):
    cell = st.stage_cell(tmp_path, "c", lib_tree, ["app"], ["flag.txt", "d/x.txt"])
    assert (cell.path / "flag.txt").read_bytes() == st.PLACEHOLDER_CONTENT
    assert (cell.path / "d/x.txt").read_bytes() == st.PLACEHOLDER_CONTENT
    assert b"{" not in st.PLACEHOLDER_CONTENT


@needs_gcc
@needs_host_loader
def test_a_symlinked_dependency_is_staged_as_content(lib_tree, tmp_path):
    link = lib_tree / "lib" / "libfoo.so"
    real = lib_tree / "lib" / "libfoo.so.real"
    link.rename(real)
    link.symlink_to("libfoo.so.real")
    try:
        cell = st.stage_cell(tmp_path, "c", lib_tree, ["app"])
        staged = cell.path / "lib" / "libfoo.so"
        assert staged.is_file() and not staged.is_symlink()
        assert staged.read_bytes() == real.read_bytes()
        assert not (cell.path / "lib" / "libfoo.so.real").exists()
    finally:
        link.unlink()
        real.rename(link)


@needs_gcc
@needs_host_loader
def test_directories_are_never_copied(lib_tree, tmp_path):
    with pytest.raises(st.StageError, match="not a file"):
        st.stage_cell(tmp_path, "c", lib_tree, ["lib"])


@pytest.mark.parametrize(
    "files, holders, message",
    [
        (["../x"], [], "non-empty relative"),
        (["/etc/passwd"], [], "non-empty relative"),
        ([], [], "non-empty relative"),
        (["tmp/a"], [], "collides"),
        (["a"], ["home/x"], "collides"),
        (["a"], ["../x"], "escapes"),
        (["a"], ["a"], "collides with a staged file"),
    ],
)
def test_bad_stage_requests_are_refused(tmp_path, files, holders, message):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a").write_text("x")
    with pytest.raises(st.StageError, match=message):
        st.stage_cell(tmp_path / "run", "c", src, files, holders)


def test_a_dot_component_in_the_cell_path_is_refused(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a").write_text("x")
    with pytest.raises(st.StageError, match="'.'-prefixed"):
        st.stage_cell(tmp_path / ".run", "c", src, ["a"])
    with pytest.raises(st.StageError, match="'.'-prefixed"):
        st.stage_cell(tmp_path / "run", ".c", src, ["a"])
    assert not (tmp_path / ".run").exists()


def test_the_target_must_be_among_the_staged_files(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a").write_text("x")
    with pytest.raises(st.StageError, match="not among"):
        st.stage_cell(tmp_path / "run", "c", src, ["a"], target="b")


def test_an_existing_cell_is_not_reused(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a").write_text("x")
    st.stage_cell(tmp_path / "run", "c", src, ["a"])
    with pytest.raises(st.StageError, match="already exists"):
        st.stage_cell(tmp_path / "run", "c", src, ["a"])


# --- the real S0 cells -------------------------------------------------------


def _truth(slug):
    path = REPO_ROOT / "benchmark" / "truth" / "s0" / f"{slug}.yaml"
    return yaml.safe_load(path.read_text())


def _source(slug):
    return (TARGETS_ROOT / slug).resolve().parent


# The staged file list the closure rules must produce for each S0 target.
S0_EXPECTED = {
    "sick_rop": ["sick_rop"],
    "rocket_blaster_xxx": [
        "flag.txt",
        "glibc/ld-linux-x86-64.so.2",
        "glibc/libc.so.6",
        "rocket_blaster_xxx",
    ],
    "snow_scan": ["snowscan"],
    "ancient_interface": ["ancient_interface"],
    "auth-or-out": ["auth-or-out"],
    "sabotage": ["glibc/ld-linux-x86-64.so.2", "glibc/libc.so.6", "sabotage"],
    "bon-nie-appetit": [
        "bon-nie-appetit",
        "glibc/ld-linux-x86-64.so.2",
        "glibc/libc.so.6",
    ],
}


@needs_targets
@pytest.mark.parametrize("slug", S0_SLUGS)
def test_s0_cells_hold_exactly_the_binary_closure_and_placeholders(slug, tmp_path):
    truth = _truth(slug)
    stage = truth["stage"]
    cell = st.stage_cell(
        tmp_path, f"{slug}-pwn-r1", _source(slug), stage["files"], stage["placeholders"],
        target=(TARGETS_ROOT / slug).resolve().name,
    )  # fmt: skip
    assert cell.files == S0_EXPECTED[slug]
    # The answer keys stay out: sources, write-ups, the server, the real flag.txt
    # content (ancient_interface and snow_scan ship one; they are not staged).
    for name in ("ancient_interface.c", "server.py", "build-docker.sh"):
        assert not (cell.path / name).exists()
    if slug in ("snow_scan", "ancient_interface"):
        assert not (cell.path / "flag.txt").exists()
    if slug == "rocket_blaster_xxx":
        assert (cell.path / "flag.txt").read_bytes() == st.PLACEHOLDER_CONTENT


@needs_targets
def test_s0_staging_leaves_the_source_tree_untouched(tmp_path):
    source = _source("rocket_blaster_xxx")
    before = sorted(p.name for p in source.rglob("*"))
    st.stage_cell(tmp_path, "c", source, ["rocket_blaster_xxx"], ["flag.txt"])
    assert sorted(p.name for p in source.rglob("*")) == before
