#!/usr/bin/env bash
# Follow-up Mythos 5-2 self-review with execution allowed (single thread).
# Waits for the fold run, stages ROADMAP-FINAL.md, then runs one Mythos session in the scratch tree.
set -u
V=/tmp/mythos-verify
R=/tmp/mythos-review
MODEL=claude-mythos-5-2
until [ -s "$R/out/FOLD.meta" ]; do sleep 20; done
cp "$R/out/FOLD.md" "$V/tree/_review/ROADMAP-FINAL.md"
cd "$V/tree" || exit 1
s=$(date +%s)
timeout 14400 claude -p --model "$MODEL" \
  --tools "Read,Grep,Glob,Bash,Write,Edit" --allowedTools "Read,Grep,Glob,Bash,Write,Edit" \
  --setting-sources "" --no-session-persistence --strict-mcp-config --output-format json \
  < "$V/prompts/VERIFY.md" > "$V/out/VERIFY.json" 2> "$V/out/VERIFY.err"
rc=$?
python3 - "$V/out/VERIFY.json" "$V/out/VERIFY.md" "$V/out/VERIFY.meta" "$rc" "$(( $(date +%s) - s ))" <<'EOF'
import json, sys
src, md, meta, rc, secs = sys.argv[1:6]
try:
    d = json.load(open(src))
except Exception as e:
    open(meta, "w").write(f"rc={rc} secs={secs} PARSE_FAIL {e}\n"); sys.exit(0)
open(md, "w").write(d.get("result") or "")
models = list((d.get("modelUsage") or {}).keys())
open(meta, "w").write(
    f"rc={rc} secs={secs} is_error={d.get('is_error')} turns={d.get('num_turns')} "
    f"models={models} cost_usd={d.get('total_cost_usd')} result_chars={len(d.get('result') or '')} "
    f"denials={len(d.get('permission_denials') or [])}\n")
EOF
echo "VERIFY DONE $(cat "$V/out/VERIFY.meta")"
