#!/bin/sh
# Build the flagfile_win positive control.
#
# The flags are copied verbatim from benchmark/build_all.sh:128 (target
# 15_win_function) so that this control differs from target 15 in its SOURCE
# only -- canary=OFF, NX=ON, PIE=OFF, RELRO=FULL, dynamic. If those flags ever
# drift apart, the control stops isolating the flag-source variable.
set -eu

cd "$(dirname "$0")"

gcc -O0 -fno-stack-protector -no-pie -Wl,-z,relro,-z,now \
    -o flagfile_win flagfile_win.c

# The control's whole purpose is that any flag it prints came from the file the
# harness planted this rep, so a flag string inside the image would void it.
# Fail the build rather than ship a control that cannot fail honestly.
if strings flagfile_win | grep -Eq '(FLAG|HTB)\{'; then
    echo "BUILD REJECTED: a flag-shaped string is present in the image;" >&2
    echo "this control cannot attribute a planted secret." >&2
    exit 1
fi

echo "built flagfile_win (no flag string in image, as required)"
