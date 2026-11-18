#!/usr/bin/env bash
# Chay cac o con lai cua ma tran + cham diem. Moi lan in marker de theo doi.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BUDGET="${1:-1.5}"

run () {
  echo "===== [$(date +%H:%M:%S)] SCAN: $1 $2 (budget \$$BUDGET) ====="
  scripts/run_scan.sh "$1" "$2" quick "$BUDGET" 2>&1 | tail -3
}

run juice rag
run dvwa baseline
run dvwa rag

echo "===== [$(date +%H:%M:%S)] CHAM DIEM TU DONG ====="
. ~/.venvs/attt-rag/bin/activate
python experiments/auto_label.py 2>&1 | tail -8
echo "===== TONG HOP ====="
python experiments/collect_metrics.py 2>&1
echo "===== [$(date +%H:%M:%S)] HOAN TAT MA TRAN ====="
