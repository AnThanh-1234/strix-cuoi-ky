#!/usr/bin/env bash
# Chay 1 lan thuc nghiem Strix.  (chay trong WSL, user thuong)
#
#   scripts/run_scan.sh <target> <baseline|rag> [scan_mode] [budget_usd]
#
#   target    : juice | dvwa | <URL bat ky trong lab>
#   baseline  : Strix nguyen ban (khong co Knowledge Base)
#   rag       : Strix + MCP server owasp_kb (tra cuu OWASP/CWE trong luc quet)
#   scan_mode : quick | standard | deep      (mac dinh: standard)
#   budget    : gioi han chi phi LLM, USD     (mac dinh: 3)
#
# Model lay tu experiments/.env (STRIX_LLM, LLM_API_KEY, [LLM_API_BASE]).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXP="$ROOT/experiments"
export PATH="$HOME/.local/bin:$PATH"

TARGET_NAME="${1:?target: juice|dvwa|URL}"
MODE="${2:?mode: baseline|rag}"
SCAN_MODE="${3:-standard}"
BUDGET="${4:-3}"

[ -f "$EXP/.env" ] || { echo "Thieu $EXP/.env (copy tu experiments/.env.example)"; exit 1; }
set -a; . "$EXP/.env"; set +a
: "${STRIX_LLM:?Dat STRIX_LLM trong experiments/.env}"
export STRIX_TELEMETRY="${STRIX_TELEMETRY:-false}"
export STRIX_NO_UPDATE_CHECK=1

"$ROOT/scripts/lab.sh" up >/dev/null

BASE_INSTR="Authorized test of an intentionally vulnerable LAB application. Stay strictly within the given target URL; do not attack any other host."
# Goi y van hanh cho model nho (ap dung NHU NHAU cho baseline va rag de so sanh cong bang)
if [ "${SMALL_MODEL_HINTS:-0}" = "1" ]; then
  BASE_INSTR="$BASE_INSTR The web_search tool is NOT configured; do not use it. Start by sending real HTTP requests to the target to map pages and API endpoints. Do not call finish_scan until you have tested the application with real requests across several vulnerability classes and reported every confirmed issue."
fi
case "$TARGET_NAME" in
  juice)
    docker restart juice-shop >/dev/null           # reset trang thai (DB in-memory)
    "$ROOT/scripts/lab.sh" wait juice
    URL="http://host.docker.internal:3000"
    INSTR="$BASE_INSTR Target is OWASP Juice Shop (Angular SPA + REST API under /rest and /api)." ;;
  dvwa)
    docker restart dvwa >/dev/null
    "$ROOT/scripts/lab.sh" wait dvwa
    "$ROOT/scripts/lab.sh" dvwa-setup
    URL="http://host.docker.internal:8080"
    INSTR="$BASE_INSTR Target is DVWA. Login with admin:password. Security level cookie: security=low." ;;
  *)
    URL="$TARGET_NAME"; INSTR="$BASE_INSTR" ;;
esac

LABEL="$(date +%Y%m%d-%H%M%S)_${TARGET_NAME//[^a-zA-Z0-9]/_}_${MODE}"
mkdir -p "$EXP/configs" "$EXP/strix_runs"

if [ "$MODE" = "rag" ]; then
  MCP_CFG="$EXP/configs/mcp_${LABEL}.json"
  cat > "$MCP_CFG" <<EOF
[
  {
    "name": "owasp_kb",
    "transport": "stdio",
    "command": "$HOME/.venvs/attt-rag/bin/python",
    "args": ["$ROOT/rag/mcp_server.py"],
    "env": {"KB_RUN_LABEL": "$LABEL", "KB_TOOL_LOG": "$EXP/kb_tool_calls.jsonl"},
    "notes": "Local OWASP knowledge base (Cheat Sheet Series, Web Security Testing Guide, MITRE CWE) + live NVD CVE lookup. Query it for official test procedures before testing a vulnerability class, for the correct CWE, and for remediation guidance before reporting.",
    "active_tools": ["search_security_kb", "get_cwe", "lookup_cve"],
    "session_timeout_seconds": 90
  }
]
EOF
  INSTR="$INSTR You have an MCP knowledge base 'owasp_kb'. Before testing each vulnerability class call search_security_kb with source='wstg' for the OWASP test procedure; before reporting a finding call it with source='cheatsheet' (and get_cwe) to confirm the CWE and remediation, and cite the returned sources. Use lookup_cve for fingerprinted component versions."
elif [ "$MODE" = "baseline" ]; then
  MCP_CFG="$EXP/configs/mcp_none.json"; echo "[]" > "$MCP_CFG"
else
  echo "mode phai la baseline|rag"; exit 1
fi

BEFORE=$("$ROOT/scripts/lab.sh" juice-solved 2>/dev/null || echo "")
echo "[*] $LABEL  model=$STRIX_LLM  scan=$SCAN_MODE  budget=\$$BUDGET  target=$URL"
START=$(date +%s)
cd "$EXP"
before_runs=$(ls -1 strix_runs 2>/dev/null | sort)
set +e
strix -n --target "$URL" --instruction "$INSTR" -m "$SCAN_MODE" --max-budget "$BUDGET" \
      --mcp-config "$MCP_CFG" 2>&1 | tee "$EXP/configs/${LABEL}.log"
RC=${PIPESTATUS[0]}
set -e
END=$(date +%s)
RUN_DIR=$(comm -13 <(echo "$before_runs") <(ls -1 strix_runs | sort) | tail -1)
AFTER=""
if [ "$TARGET_NAME" = "juice" ]; then
  AFTER=$("$ROOT/scripts/lab.sh" juice-solved 2>/dev/null || echo "")
  # snapshot challenge (bang chung khach quan cho auto_label.py)
  [ -n "$RUN_DIR" ] && curl -fs http://localhost:3000/api/Challenges/ | python3 -c \
    'import json,sys; print(json.dumps([{k: c[k] for k in ("key","name","category","difficulty","solved")} for c in json.load(sys.stdin)["data"]], indent=1))' \
    > "$EXP/strix_runs/$RUN_DIR/juice_challenges.json" || true
fi

[ -f "$EXP/runs.csv" ] || echo "label,target,mode,model,scan_mode,budget,run_dir,seconds,exit_code,juice_solved_after" > "$EXP/runs.csv"
echo "$LABEL,$TARGET_NAME,$MODE,$STRIX_LLM,$SCAN_MODE,$BUDGET,$RUN_DIR,$((END-START)),$RC,$AFTER" >> "$EXP/runs.csv"
echo "[+] Xong sau $((END-START))s, exit=$RC, run_dir=strix_runs/$RUN_DIR (juice solved: ${BEFORE:-?} -> ${AFTER:-?})"
