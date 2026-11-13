#!/usr/bin/env bash
# Dieu khien LLM server tren Kaggle GPU (chay trong WSL).
#
#   scripts/kaggle_llm.sh start [hours]   push kernel len Kaggle (T4 x2), cho tunnel, ghi cau hinh vao experiments/.env
#   scripts/kaggle_llm.sh url             doc lai URL tunnel tu log kernel va cap nhat .env
#   scripts/kaggle_llm.sh test            goi thu model qua tunnel (chat + tool calling)
#   scripts/kaggle_llm.sh status          trang thai kernel
#   scripts/kaggle_llm.sh stop            tat server (tiet kiem quota GPU 30h/tuan)
#
# Bien tuy chinh (trong experiments/.kaggle_llm, tu tao lan dau):
#   KAGGLE_LLM_MODELS="qwen3:14b,gemma3:12b"   model dau = model cho Strix, model 2 = giam khao (judge)
#   KAGGLE_LLM_CTX=40960
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXP="$ROOT/experiments"
export PATH="$HOME/.local/bin:$PATH"
CFG="$EXP/.kaggle_llm"
ENVF="$EXP/.env"

if [ ! -f "$CFG" ]; then
  cat > "$CFG" <<EOF
KAGGLE_LLM_KEY=$(openssl rand -hex 24)
KAGGLE_LLM_MODELS=qwen3:14b,gemma3:12b
KAGGLE_LLM_CTX=40960
KAGGLE_LLM_SLUG=attt-strix-llm-server
EOF
  chmod 600 "$CFG"
fi
. "$CFG"
USER_NAME=$(kaggle config view | awk -F': ' '/username/{print $2}')
KID="$USER_NAME/$KAGGLE_LLM_SLUG"
MAIN_MODEL="${KAGGLE_LLM_MODELS%%,*}"
JUDGE_MODEL="${KAGGLE_LLM_MODELS#*,}"; [ "$JUDGE_MODEL" = "$KAGGLE_LLM_MODELS" ] && JUDGE_MODEL="$MAIN_MODEL"

get_url () {
  # -f: log truc tiep cua phien dang chay (khong co -f chi tra log sau khi kernel ket thuc)
  { timeout 25 kaggle kernels logs -f "$KID" 2>/dev/null || true; } \
    | grep -oE 'TUNNEL_URL=https://[a-z0-9-]+\.trycloudflare\.com' | tail -1 | cut -d= -f2
}

write_env () {
  local url="$1"
  touch "$ENVF"; chmod 600 "$ENVF"
  # xoa block cu roi ghi block moi
  sed -i '/^# >>> kaggle-llm >>>/,/^# <<< kaggle-llm <<</d' "$ENVF"
  sed -i -E 's/^(STRIX_LLM|LLM_API_KEY|LLM_API_BASE)=/# &/' "$ENVF"
  cat >> "$ENVF" <<EOF
# >>> kaggle-llm >>>  (tu sinh boi scripts/kaggle_llm.sh - $(date '+%F %T'))
STRIX_LLM=openai/$MAIN_MODEL
LLM_API_BASE=$url/v1
LLM_API_KEY=$KAGGLE_LLM_KEY
LLM_TIMEOUT=900
STRIX_REASONING_EFFORT=none
STRIX_PROMPT_CACHE=false
STRIX_CONTEXT_FALLBACK_TOKENS=$KAGGLE_LLM_CTX
STRIX_CONTEXT_BUFFER_TOKENS=8000
STRIX_CONTEXT_KEEP_TOKENS=6000
STRIX_TOOL_OUTPUT_MAX_TOKENS=3000
STRIX_FORCE_REQUIRED_TOOL_CHOICE=true
SMALL_MODEL_HINTS=1
JUDGE_MODEL=$JUDGE_MODEL
JUDGE_API_BASE=$url
JUDGE_API_KEY=$KAGGLE_LLM_KEY
# <<< kaggle-llm <<<
EOF
  echo "[+] Da ghi cau hinh vao $ENVF  (STRIX_LLM=openai/$MAIN_MODEL, judge=$JUDGE_MODEL)"
}

case "${1:-status}" in
  start)
    HOURS="${2:-8}"
    K="$EXP/kaggle_kernel"; mkdir -p "$K"
    sed -e "s|__API_KEY__|$KAGGLE_LLM_KEY|" -e "s|__MODELS__|$KAGGLE_LLM_MODELS|" \
        -e "s|__MAX_HOURS__|$HOURS|" -e "s|__CTX__|$KAGGLE_LLM_CTX|" \
        -e "s|__PARALLEL__|${KAGGLE_LLM_PARALLEL:-2}|" -e "s|__MAX_LOADED__|${KAGGLE_LLM_MAX_LOADED:-2}|" \
        "$ROOT/kaggle/llm_server.py" > "$K/llm_server.py"
    cat > "$K/kernel-metadata.json" <<EOF
{
  "id": "$KID",
  "title": "$KAGGLE_LLM_SLUG",
  "code_file": "llm_server.py",
  "language": "python",
  "kernel_type": "script",
  "is_private": true,
  "enable_gpu": true,
  "enable_internet": true,
  "dataset_sources": [], "competition_sources": [], "kernel_sources": []
}
EOF
    kaggle kernels push -p "$K" --accelerator NvidiaTeslaT4 -t $(( ${HOURS%.*} * 3600 + 900 ))
    echo "[*] Cho kernel cai Ollama + tai model + mo tunnel (thuong 8-15 phut)..."
    for i in $(seq 1 90); do
      url=$(get_url || true)
      if [ -n "$url" ]; then
        echo "[+] Tunnel: $url"; write_env "$url"; "$0" test; exit 0
      fi
      st=$(kaggle kernels status "$KID" 2>/dev/null | grep -oE '"[A-Z_]+"|status "?[a-zA-Z_.]+' | tail -1)
      case "$st" in *ERROR*|*error*|*CANCEL*|*cancel*) echo "!! Kernel loi: $st"; kaggle kernels logs "$KID" | tail -30; exit 1;; esac
      printf "\r  ... %3ds  %s" $((i*20)) "$st"; sleep 20
    done
    echo; echo "!! Het thoi gian cho. Xem: kaggle kernels logs $KID"; exit 1 ;;
  url)
    url=$(get_url); [ -n "$url" ] || { echo "Chua co URL"; exit 1; }
    echo "$url"; write_env "$url" ;;
  test)
    set -a; . "$ENVF"; set +a
    echo "[*] health:"; curl -fsS -H "Authorization: Bearer $LLM_API_KEY" "${LLM_API_BASE%/v1}/__health"; echo
    echo "[*] chat + tool calling ($MAIN_MODEL):"
    t0=$(date +%s.%N)
    curl -fsS "$LLM_API_BASE/chat/completions" -H "Authorization: Bearer $LLM_API_KEY" -H 'Content-Type: application/json' -d '{
      "model": "'"$MAIN_MODEL"'",
      "messages": [{"role":"user","content":"Check if http://lab:3000/rest/products/search?q= is vulnerable to SQL injection. Use the tool."}],
      "tools": [{"type":"function","function":{"name":"http_request","description":"Send an HTTP request","parameters":{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"}},"required":["url"]}}}]
    }' | python3 -c 'import json,sys; m=json.load(sys.stdin)["choices"][0]["message"]; u=m.get("tool_calls"); print("tool_calls:", json.dumps([c["function"] for c in u]) if u else None); print("content:", (m.get("content") or "")[:200])'
    python3 -c "import time; print('  thoi gian: %.1fs' % (time.time() - $t0))" ;;
  status)
    kaggle kernels status "$KID" ;;
  stop)
    set -a; . "$ENVF"; set +a
    curl -fsS -X POST -H "Authorization: Bearer $LLM_API_KEY" "${LLM_API_BASE%/v1}/__stop" && echo " -> server se tat trong <30s" ;;
  *) echo "usage: $0 start [hours]|url|test|status|stop"; exit 1 ;;
esac
