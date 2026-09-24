"""Drive probe scripts through run_bench.py's OWN provisioning, negative
controls, independent_verify() and classify() -- unmodified, exactly as the
harness does it. Used to prove/disprove harness soundness.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent                   # benchmark/
sys.path.insert(0, str(BENCH))

import run_bench as rb                 # noqa: E402

NON_EXPLOITING = ["donothing_interactive.py", "donothing_subprocess.py",
                  "hardcoded_flag.py", "pure_python_scrape.py"]
GENUINE = {"02_ret2plt_system": ["real_exploit_02.py",
                                 "real_exploit_02_explicit.py"]}

corpus = rb.Corpus(root=rb.DEFAULT_CORPUS_DIR, manifest=rb.DEFAULT_CORPUS_YAML)
TARGETS = sys.argv[1:] or ["13_off_by_one", "15_win_function"]

print(f"VERIFY_STDIN = {rb.VERIFY_STDIN!r}  ({len(rb.VERIFY_STDIN)} bytes)\n")
for slug in TARGETS:
    secret = rb.mint_secret_flag()
    try:
        rb.build_with_secret(corpus, slug, secret)
    except rb.ProvisionError as e:
        print(f"{slug}: PROVISION FAILED: {e}")
        continue
    flag = corpus.flag_file(slug).read_text().strip()
    tdir = corpus.target_dir(slug)
    control = rb.negative_control(corpus, slug, flag, 10.0)
    print(f"{slug}  secret={flag}")
    print(f"  negative control leaked: {control['flag_leaked_without_exploit'] or 'NONE'}"
          f"   statically_extractable_from_binary="
          f"{control['flag_statically_extractable_from_binary']}")

    for probe in NON_EXPLOITING + GENUINE.get(slug, []):
        kind = "GENUINE " if probe in GENUINE.get(slug, []) else "NO-EXPLOIT"
        audit = rb.inspect_generated_script(HERE / probe, flag)
        v = rb.independent_verify(HERE / probe, tdir, flag, 10.0)
        status, reason, cause = rb.classify(None, v, control, audit)
        verdict = "ok"
        if kind.strip() == "NO-EXPLOIT" and status == "SUCCESS":
            # Distinguish a NEW hole from the documented weak-attribution one:
            # on a target whose flag is compiled in, an unsandboxed script can
            # always read it, and the harness now says so in the reason.
            verdict = ("*** FALSE POSITIVE (known: weak-attribution target) ***"
                       if "WEAK ATTRIBUTION" in reason
                       else "*** FALSE POSITIVE -- NEW HOLE ***")
        if kind.strip() == "GENUINE" and status != "SUCCESS":
            verdict = "*** FALSE NEGATIVE ***"
        print(f"  [{kind}] {probe:<30} -> {status:<8} "
              f"flag={v['flag_found']} shell={v['shell_proven']} "
              f"cause={cause or '-':<28} {verdict}")
    print()
