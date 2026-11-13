#!/usr/bin/env bash
# Tai cac nguon tri thuc cho Knowledge Base (chay trong WSL).
#   - OWASP Cheat Sheet Series  (CC BY-SA 4.0)  -> phong chong / khac phuc
#   - OWASP WSTG                (CC BY-SA 4.0)  -> phuong phap kiem thu
#   - MITRE CWE (XML)           (CWE Terms of Use) -> phan loai diem yeu
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/kb/sources"
mkdir -p "$SRC"

clone_or_pull () {
  local url="$1" dir="$2"
  if [ -d "$dir/.git" ]; then
    git -C "$dir" pull --ff-only --depth 1 || true
  else
    git clone --depth 1 "$url" "$dir"
  fi
}

clone_or_pull https://github.com/OWASP/CheatSheetSeries.git "$SRC/CheatSheetSeries"
clone_or_pull https://github.com/OWASP/wstg.git             "$SRC/wstg"

echo "[*] Tai CWE XML..."
curl -fsSL -o "$SRC/cwec_latest.xml.zip" https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
(cd "$SRC" && rm -f cwec_v*.xml && unzip -o -q cwec_latest.xml.zip)

for d in CheatSheetSeries wstg; do
  echo "$d commit: $(git -C "$SRC/$d" rev-parse --short HEAD)"
done
ls -1 "$SRC"/cwec_v*.xml
