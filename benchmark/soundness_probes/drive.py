"""Drive probe scripts through run_bench.py's OWN provisioning, negative
controls, independent_verify(), behavioural attribution and classify() --
unmodified, exactly as the harness does it. Used to prove/disprove harness
soundness.

THE ONE RULE THIS FILE MUST OBEY
--------------------------------
It has to exercise the SAME code path as run_one(). An earlier version called
classify() without the `attribution=` argument, so it never ran behavioural
attribution at all -- the single most important check in the harness. It
therefore reported "no holes" while testing a path the harness does not use,
which is worse than not testing: a validation tool that cannot fail gives
false assurance. If run_one() gains another input to classify(), it must be
wired in here too.

Both modes are checked. A non-exploiting probe must be rejected under the
DEFAULT settings as well as under --strict-attribution; being rejected only
under strict would mean the default run is scoreable by a script that never
exploited anything.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent                   # benchmark/
sys.path.insert(0, str(BENCH))

import attribution as at              # noqa: E402
import run_bench as rb                # noqa: E402

NON_EXPLOITING = ["donothing_interactive.py", "donothing_subprocess.py",
                  "hardcoded_flag.py", "pure_python_scrape.py"]
GENUINE = {"02_ret2plt_system": ["real_exploit_02.py",
                                 "real_exploit_02_explicit.py"]}

corpus = rb.Corpus(root=rb.DEFAULT_CORPUS_DIR, manifest=rb.DEFAULT_CORPUS_YAML)
TARGETS = sys.argv[1:] or ["13_off_by_one", "15_win_function"]
TRACES = Path(rb.DEFAULT_CORPUS_DIR).parent / "results" / "_probe_attribution"

failures: list[str] = []
# Counted so the closing verdict can only claim what actually ran. The genuine
# exploits exist for one target, so a sweep that omits it proves nothing about
# false negatives -- and must not print a sentence implying otherwise.
checked = {"NO-EXPLOIT": 0, "GENUINE": 0}

print(f"VERIFY_STDIN = {rb.VERIFY_STDIN!r}  ({len(rb.VERIFY_STDIN)} bytes)\n")
for slug in TARGETS:
    secret = rb.mint_secret_flag()
    try:
        rb.build_with_secret(corpus, slug, secret)
    except rb.ProvisionError as e:
        print(f"{slug}: PROVISION FAILED: {e}")
        failures.append(f"{slug}: provisioning failed")
        continue
    flag = corpus.flag_file(slug).read_text().strip()
    tdir = corpus.target_dir(slug)
    bp = corpus.binary(slug).resolve()
    control = rb.negative_control(corpus, slug, flag, 10.0)
    print(f"{slug}  secret={flag}")
    print(f"  negative control leaked: {control['flag_leaked_without_exploit'] or 'NONE'}"
          f"   statically_extractable_from_binary="
          f"{control['flag_statically_extractable_from_binary']}")

    for probe in NON_EXPLOITING + GENUINE.get(slug, []):
        kind = "GENUINE " if probe in GENUINE.get(slug, []) else "NO-EXPLOIT"
        audit = rb.inspect_generated_script(HERE / probe, flag)
        v = rb.independent_verify(HERE / probe, tdir, flag, 10.0)

        # Exactly what run_one() does: witness only when there is a flag to
        # attribute, and hand the result to classify().
        if v["flag_found"]:
            attribution = at.witness(
                script_path=HERE / probe,
                target_dir=tdir,
                target_binary=bp,
                expected_flag=flag,
                stdin_bytes=rb.VERIFY_STDIN,
                timeout=10.0,
                env=rb._script_env(None),
                python=sys.executable,
                trace_dir=TRACES / slug / f"{probe}_attribution",
            )
        else:
            attribution = {"available": False,
                           "unavailable_reason": "not run (no flag to attribute)"}

        outcomes = {}
        for strict in (False, True):
            outcomes[strict] = rb.classify(
                None, v, control, audit,
                strict_attribution=strict, attribution=attribution)

        notes = []
        for strict, (status, _reason, cause) in outcomes.items():
            mode = "strict" if strict else "default"
            if kind.strip() == "NO-EXPLOIT" and status == "SUCCESS":
                notes.append(f"*** FALSE POSITIVE in {mode} mode ***")
                failures.append(f"{slug}/{probe}: credited in {mode} mode")
            if kind.strip() == "GENUINE" and status != "SUCCESS":
                notes.append(f"*** FALSE NEGATIVE in {mode} mode ***")
                failures.append(f"{slug}/{probe}: not credited in {mode} mode")

        checked[kind.strip()] += 1
        d_status, _dr, d_cause = outcomes[False]
        s_status, _sr, s_cause = outcomes[True]
        print(f"  [{kind}] {probe:<30} default={d_status:<8} "
              f"strict={s_status:<8} flag={str(v['flag_found']):<5} "
              f"shell={str(v['shell_proven']):<5} "
              f"cause={d_cause or '-':<26} {' '.join(notes) or 'ok'}")
        # The attribution verdict is the load-bearing evidence, so print it
        # rather than only the status it produced.
        if attribution.get("available"):
            print(f"      attribution: credited="
                  f"{[w['chain'] for w in attribution.get('credited_writers') or []]} "
                  f"uncredited="
                  f"{[w['chain'] for w in attribution.get('uncredited_writers') or []]}")
        else:
            print(f"      attribution: UNAVAILABLE "
                  f"({attribution.get('unavailable_reason')})")
    print()

print("-" * 70)
if failures:
    print(f"FAILURES: {len(failures)}")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("FAILURES: 0")
print(f"  {checked['NO-EXPLOIT']} non-exploiting probe run(s) rejected in BOTH "
      f"default and strict mode.")
if checked["GENUINE"]:
    print(f"  {checked['GENUINE']} genuine exploit run(s) credited in both modes.")
else:
    print("  0 genuine exploit runs -- this sweep says NOTHING about false")
    print("  negatives. Include 02_ret2plt_system to test that direction.")
