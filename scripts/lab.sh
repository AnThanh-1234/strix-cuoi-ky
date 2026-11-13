#!/usr/bin/env bash
# Quan ly lab (chay trong WSL).
#   scripts/lab.sh up            khoi dong Docker daemon + Juice Shop + DVWA
#   scripts/lab.sh down          tat cac app muc tieu
#   scripts/lab.sh status        trang thai
#   scripts/lab.sh wait <juice|dvwa>
#   scripts/lab.sh dvwa-setup    tao/reset database DVWA
#   scripts/lab.sh juice-solved  so challenge Juice Shop da giai / tong
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

ensure_docker () {
  if ! docker info >/dev/null 2>&1; then
    echo "[*] Khoi dong Docker daemon (can sudo)..." >&2
    sudo service docker start >/dev/null
    for _ in $(seq 1 20); do docker info >/dev/null 2>&1 && break; sleep 1; done
  fi
}

case "${1:-status}" in
  up)
    ensure_docker
    docker compose -f "$ROOT/targets/docker-compose.yml" up -d
    ;;
  down)
    docker compose -f "$ROOT/targets/docker-compose.yml" down ;;
  status)
    docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' ;;
  wait)
    port=$([ "${2:-juice}" = "dvwa" ] && echo 8080 || echo 3000)
    for _ in $(seq 1 60); do curl -fs -o /dev/null "http://localhost:$port" && exit 0; sleep 2; done
    echo "timeout cho $2" >&2; exit 1 ;;
  dvwa-setup)
    jar=$(mktemp)
    tok=$(curl -s -c "$jar" http://localhost:8080/setup.php | grep -oP "user_token' value='\K[0-9a-f]+")
    curl -s -b "$jar" -c "$jar" -o /dev/null -d "create_db=Create+%2F+Reset+Database&user_token=$tok" http://localhost:8080/setup.php
    rm -f "$jar"; echo "DVWA database ready" ;;
  juice-solved)
    curl -fs http://localhost:3000/api/Challenges/ | python3 -c \
      'import json,sys; d=json.load(sys.stdin)["data"]; print("%d/%d" % (sum(c["solved"] for c in d), len(d)))' ;;
  *) echo "usage: $0 up|down|status|wait|dvwa-setup|juice-solved"; exit 1 ;;
esac
