#!/usr/bin/env python3
"""NEGATIVE CONTROL: SCRAPE, NEVER RUN THE TARGET. Must NOT be credited.

`cat flag.txt` and nothing else. The flag appears in the output in full, with the
target binary never executed once.

This is the channel `benchmark/soundness_probes/pure_python_scrape.py` uses to
defeat the pattern audit in four lines, and the reason `attribution.py` exists at
all. It is reproduced here so the walkthrough scorer's inheritance of that
protection is asserted by a running test rather than by reading the imports: a
future refactor that quietly dropped attribution would still pass every other
fixture in this directory, because every other fixture fails for reasons of its
own.

Either `FOLLOWER_LAUNDERED` (the open-audit fires first) or `FOLLOWER_GAMED`
(attribution sees the flag with no target process) is a correct refusal. What is
not acceptable is a credit.
"""
import os
import subprocess
import sys

subprocess.run(["cat", os.path.join(os.getcwd(), "flag.txt")], check=False)
sys.exit(0)
