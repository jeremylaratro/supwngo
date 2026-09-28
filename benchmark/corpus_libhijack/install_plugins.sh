#!/usr/bin/env bash
# Install the LEGITIMATE extension module for benchmark/corpus_libhijack/.
#
# WHY THIS SCRIPT EXISTS AT ALL -- STATED PLAINLY RATHER THAN WORKED AROUND
# ------------------------------------------------------------------------
# `benchmark/build_all.sh` compiles exactly ONE artifact per target directory:
# `<slug>.c` -> `<slug>`, with the flags in that directory's `cflags` appended to
# that single gcc invocation. `cflags` therefore CANNOT express this family's two
# extra build products:
#
#   1. the legitimate extension module (a SHARED OBJECT, a second gcc output), and
#   2. for libhj_13, a real sibling library that has to EXIST AT LINK TIME so the
#      executable can be linked against it and get a DT_NEEDED entry.
#
# Rather than silently building a different program (a target with no plugin to
# load, or a libhj_13 with no DT_NEEDED at all), the family splits provisioning in
# two and documents it. Run order matters:
#
#   benchmark/corpus_libhijack/install_plugins.sh                 # this script FIRST
#   SUPWNGO_BENCH_CORPUS=benchmark/corpus_libhijack \
#       benchmark/build_all.sh                                    # then the targets
#
# The order is load-bearing only for libhj_13: its `cflags` carries
# `-L/tmp/supwngo_libhj_linkdir -lsupwngoext`, and that directory is created here.
# An absolute /tmp path is used on purpose -- a committed `cflags` must not contain
# a host-specific checkout path, and `-L` is resolved against gcc's cwd (which is
# whatever directory build_all.sh happened to be invoked from), so a relative -L
# would silently drop the DT_NEEDED entry on any other cwd. Verify after building:
#
#   readelf -d libhj_13_runpath_origin/libhj_13_runpath_origin | grep -E 'NEEDED|RPATH'
#
# Idempotent: every step is an unconditional rebuild/copy.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/supwngo_ext.c"
SONAME="libsupwngoext.so.1"

# Link-time search directory for libhj_13. See the note above for why it is an
# absolute /tmp path and not a path inside the corpus.
LINKDIR="/tmp/supwngo_libhj_linkdir"

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

# The legitimate module. `-Wl,-soname` matters for libhj_12 and libhj_13: the
# loader records the SONAME (not the path) as the DT_NEEDED / dlopen key, and the
# family's bare-soname variant is only meaningful if that key is a soname.
gcc -shared -fPIC -O0 -Wl,-soname,"$SONAME" -o "$BUILD/$SONAME" "$SRC"
echo "==> built $SONAME (soname $(readelf -d "$BUILD/$SONAME" | awk '/SONAME/ {print $NF}'))"

install_to() {
    local dir="$1"
    mkdir -p "$dir"
    cp "$BUILD/$SONAME" "$dir/$SONAME"
    chmod 755 "$dir/$SONAME"
    echo "    installed -> $dir/$SONAME"
}

# libhj_10: dlopen("./plugins/<soname>") -- resolved against the CWD, so the
#           legitimate deployment is "run me from my own directory".
install_to "$HERE/libhj_10_dlopen_relative_path/plugins"

# libhj_11: dlopen("<dir>/<soname>") where <dir> defaults to the binary's own
#           plugins/ directory and is overridable by an environment variable.
install_to "$HERE/libhj_11_dlopen_dir_from_env/plugins"

# libhj_12: dlopen("<soname>") with no slash. Legitimate resolution comes from
#           the executable's DT_RUNPATH ($ORIGIN/plugins).
install_to "$HERE/libhj_12_dlopen_bare_soname/plugins"

# libhj_13: DT_NEEDED sibling. `vendor/` is the SECOND DT_RPATH entry and holds
#           the legitimate copy; `lib/` is the FIRST entry and is deliberately
#           left EMPTY -- an early, writable, empty RUNPATH/RPATH entry is the
#           defect this variant carries.
install_to "$HERE/libhj_13_runpath_origin/vendor"
mkdir -p "$HERE/libhj_13_runpath_origin/lib"
echo "    left empty -> $HERE/libhj_13_runpath_origin/lib (first RPATH entry)"
install_to "$LINKDIR"

# libhj_14: the bundled module, loaded when the scanned drop-in directory is
#           empty. The scan itself is the defect, not this file.
install_to "$HERE/libhj_14_plugin_dir_scan/plugins"

# libhj_90 (the negative control) deliberately gets NOTHING installed here: its
# extension module is a vendor system object at an absolute path under a
# root-owned directory (/lib/x86_64-linux-gnu/libz.so.1), which is the only way a
# same-uid corpus can honestly express "a directory the attacker cannot write".
# See corpus_libhijack.yaml, section "THE CONTROL'S HONEST LIMIT".
echo "==> libhj_90_neg_absolute_verified: nothing to install (loads a system object)"

echo "Done. Now build the targets:"
echo "  SUPWNGO_BENCH_CORPUS=benchmark/corpus_libhijack benchmark/build_all.sh"
