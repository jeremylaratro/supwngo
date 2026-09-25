#!/usr/bin/env python3
"""Encoding fixture matrix for comparison_immediates()'s recovery regex.

Answers, per cell: does the gate constant appear as an immediate in the
disassembly at all, and does the shipped regex recover it? Widths x mnemonics
x signedness x optimisation level. Uses the EXACT objdump command the function
uses, and the EXACT shipped regex.
"""
import re, subprocess, tempfile, pathlib, sys

SHIPPED = re.compile(r"\b(?:cmp|cmpl|cmpq|test)\s+\$0x([0-9a-fA-F]+)")
EXTENDED = re.compile(
    r"\b(?:cmp|cmpb|cmpw|cmpl|cmpq|test|testb|testw|testl|testq)\s+\$0x([0-9a-fA-F]+)"
)

# width -> (ctype_signed, ctype_unsigned, scanf_fmt_signed, scanf_fmt_unsigned, constant)
WIDTHS = {
    8:  ("signed char", "unsigned char", "%hhd", "%hhu", 0xA7),
    16: ("short", "unsigned short", "%hd", "%hu", 0x1F3B),
    32: ("int", "unsigned int", "%d", "%u", 0x1337BEEF),
    64: ("long long", "unsigned long long", "%lld", "%llu", 0x1122334455667788),
}

SRC = """#include <stdio.h>
int main(void) {{
    {ctype} v;
    if (scanf("{fmt}", &v) != 1) return 1;
    if ({expr}) puts("HIT");
    return 0;
}}
"""


def build_and_scan(ctype, fmt, expr, opt, tmpdir, tag):
    c = pathlib.Path(tmpdir) / f"{tag}.c"
    b = pathlib.Path(tmpdir) / tag
    c.write_text(SRC.format(ctype=ctype, fmt=fmt, expr=expr))
    r = subprocess.run(["gcc", opt, "-o", str(b), str(c)], capture_output=True)
    if r.returncode != 0:
        return None, f"compile failed: {r.stderr.decode()[:120]}"
    # the exact command comparison_immediates() runs
    d = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", str(b)],
        capture_output=True, timeout=60,
    )
    if d.returncode != 0:
        return None, f"objdump exit {d.returncode}"
    return d.stdout.decode("latin-1", errors="ignore"), None


def main():
    rows = []
    with tempfile.TemporaryDirectory() as td:
        for width, (cs, cu, fs, fu, const) in WIDTHS.items():
            for signed, ctype, fmt in ((True, cs, fs), (False, cu, fu)):
                for mnem, expr_t in (("cmp", "v == {k}"), ("test", "(v & {k})")):
                    for opt in ("-O0", "-O2"):
                        k = f"0x{const:X}" + ("LL" if width == 64 else "")
                        expr = expr_t.format(k=k)
                        tag = f"w{width}_{'s' if signed else 'u'}_{mnem}_{opt[1:]}"
                        dis, err = build_and_scan(ctype, fmt, expr, opt, td, tag)
                        if dis is None:
                            rows.append((width, signed, mnem, opt, "COMPILE/OBJDUMP ERR", err, "", ""))
                            continue
                        hexstr = f"{const:x}"
                        # does the constant appear as ANY immediate ($0x...) at all?
                        as_imm = bool(re.search(r"\$0x0*" + hexstr + r"\b", dis, re.I))
                        # does it appear anywhere in the disassembly text at all?
                        anywhere = hexstr in dis.lower()
                        got_shipped = const in [int(m, 16) for m in SHIPPED.findall(dis)]
                        got_ext = const in [int(m, 16) for m in EXTENDED.findall(dis)]
                        # what mnemonics actually carry immediates here
                        mns = sorted(set(re.findall(
                            r"\b(cmp|cmpb|cmpw|cmpl|cmpq|test|testb|testw|testl|testq)\s+\$0x", dis)))
                        rows.append((width, signed, mnem, opt,
                                     "yes" if as_imm else ("text-only" if anywhere else "ABSENT"),
                                     "YES" if got_shipped else "no",
                                     "YES" if got_ext else "no",
                                     ",".join(mns) or "-"))

    hdr = f"{'w':>3} {'sign':>6} {'src':>5} {'opt':>4} | {'as-immediate':>13} {'shipped':>8} {'extended':>9} | mnemonics-with-imm"
    print(hdr); print("-" * len(hdr))
    for r in rows:
        w, signed, mnem, opt, as_imm, sh, ex, mns = r
        print(f"{w:>3} {'signed' if signed else 'unsign':>6} {mnem:>5} {opt:>4} | "
              f"{as_imm:>13} {sh:>8} {ex:>9} | {mns}")

    print()
    tot = len(rows)
    absent = sum(1 for r in rows if r[4] == "ABSENT")
    sh_yes = sum(1 for r in rows if r[5] == "YES")
    ex_yes = sum(1 for r in rows if r[6] == "YES")
    print(f"cells: {tot}  (non-vacuity: 4 widths x 2 signedness x 2 mnemonics x 2 opt = 32)")
    print(f"constant absent as an immediate entirely : {absent}")
    print(f"recovered by SHIPPED regex               : {sh_yes}")
    print(f"recovered by EXTENDED regex              : {ex_yes}")
    print(f"gain from extending the mnemonic list    : {ex_yes - sh_yes}")


if __name__ == "__main__":
    main()
