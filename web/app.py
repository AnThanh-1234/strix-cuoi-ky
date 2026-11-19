#!/usr/bin/env python3
"""Local Strix web console: targets, scans, history, schedules, audit and reports."""
from __future__ import annotations

import html
import json
import os
import queue
import re
import secrets
import shlex
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = Path(__file__).resolve().parent
DATA = Path(os.environ.get("STRIX_WEB_DATA", WEB / "data")).resolve()
DB = DATA / "strix_web.sqlite3"
LOG_DIR = DATA / "logs"
REPORT_DIR = DATA / "reports"
PORT = int(os.environ.get("STRIX_WEB_PORT", "8765"))
HOST = "127.0.0.1"
LOG_LIMIT = 300_000
JOB_QUEUE: queue.Queue[int] = queue.Queue()
SCAN_SUBMIT_LOCK = threading.Lock()


class ScanBusyError(Exception):
    pass


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=20000")
    return conn


def init_db() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS targets(
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, base_url TEXT NOT NULL,
          scope_note TEXT NOT NULL DEFAULT '', authorized INTEGER NOT NULL,
          authorized_at REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          created_at REAL NOT NULL, updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS scans(
          id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, target_name TEXT NOT NULL,
          target_url TEXT NOT NULL, mode TEXT NOT NULL, scan_mode TEXT NOT NULL,
          budget REAL NOT NULL, instruction TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'manual',
          schedule_id INTEGER, status TEXT NOT NULL, created_at REAL NOT NULL,
          started_at REAL, ended_at REAL, exit_code INTEGER, error TEXT NOT NULL DEFAULT '',
          run_dir TEXT NOT NULL DEFAULT '', log_path TEXT NOT NULL DEFAULT '',
          logs TEXT NOT NULL DEFAULT '', findings_json TEXT NOT NULL DEFAULT '[]',
          FOREIGN KEY(target_id) REFERENCES targets(id));
        CREATE INDEX IF NOT EXISTS scans_status_idx ON scans(status, created_at);
        CREATE TABLE IF NOT EXISTS schedules(
          id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, mode TEXT NOT NULL,
          scan_mode TEXT NOT NULL, schedule_type TEXT NOT NULL DEFAULT 'interval', interval_hours INTEGER NOT NULL, budget REAL NOT NULL,
          instruction TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
          created_at REAL NOT NULL, next_run_at REAL NOT NULL, last_run_at REAL,
          FOREIGN KEY(target_id) REFERENCES targets(id));
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY, created_at REAL NOT NULL, actor TEXT NOT NULL,
          action TEXT NOT NULL, object_type TEXT NOT NULL, object_id TEXT NOT NULL DEFAULT '',
          result TEXT NOT NULL DEFAULT 'success', details TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS reports(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, format TEXT NOT NULL,
          path TEXT NOT NULL, created_at REAL NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id));
        """)
        schedule_columns = {row[1] for row in conn.execute("PRAGMA table_info(schedules)")}
        if "schedule_type" not in schedule_columns:
            conn.execute("ALTER TABLE schedules ADD COLUMN schedule_type TEXT NOT NULL DEFAULT 'interval'")
        # A web server restart cannot safely resume a CLI process from the old process tree.
        now = time.time()
        interrupted = conn.execute("SELECT id FROM scans WHERE status IN ('Running','Queued')").fetchall()
        conn.execute("UPDATE scans SET status='Failed', ended_at=?, error='Backend restarted while scan was active.' WHERE status IN ('Running','Queued')", (now,))
        for row in interrupted:
            conn.execute("INSERT INTO audit(created_at,actor,action,object_type,object_id,result,details) VALUES(?,?,?,?,?,?,?)",
                         (now, "local operator", "scan.failed", "scan", str(row["id"]), "interrupted", "Backend restarted while scan was active."))
        conn.commit()


def audit(action: str, object_type: str, object_id: object = "", result: str = "success", details: str = "") -> None:
    safe_details = details[:1000]
    with connect() as conn:
        conn.execute("INSERT INTO audit(created_at,actor,action,object_type,object_id,result,details) VALUES(?,?,?,?,?,?,?)",
                     (time.time(), "local operator", action, object_type, str(object_id), result, safe_details))


def scrub_log(text: str) -> str:
    text = re.sub(r"(?i)(api[_-]?key|access[_-]?token|password|authorization)(\s*[:=]\s*)([^\s,;]+)",
                  r"\1\2[REDACTED]", text)
    text = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)([?&](?:token|api_key|key|password)=)[^&\s]+", r"\1[REDACTED]", text)
    text = re.sub(r"AIza[0-9A-Za-z_-]{20,}", "[REDACTED_API_KEY]", text)
    for key in ("LLM_API_KEY", "STRIX_NOTIFY_WEBHOOK"):
        secret = os.environ.get(key, "")
        if len(secret) >= 8:
            text = text.replace(secret, "[REDACTED]")
    return text


def json_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    if length < 0 or length > 1_000_000:
        raise ValueError("Request body quá lớn.")
    try:
        value = json.loads(handler.rfile.read(length) or b"{}")
    except json.JSONDecodeError as exc:
        raise ValueError("JSON không hợp lệ.") from exc
    if not isinstance(value, dict):
        raise ValueError("Request body phải là object JSON.")
    return value


def validate_url(value: object) -> str:
    url = str(value or "").strip()
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("URL phải bắt đầu bằng http:// hoặc https:// và không chứa thông tin đăng nhập.")
    if any(ch.isspace() for ch in url) or not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname):
        raise ValueError("Tên host trong URL không hợp lệ.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Cổng trong URL không hợp lệ.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Cổng trong URL không hợp lệ.")
    return url


def validate_scan_config(data: dict) -> tuple[str, str, float, str]:
    mode = data.get("mode")
    depth = data.get("scan_mode")
    if mode not in ("rag", "baseline"):
        raise ValueError("Chế độ phải là rag hoặc baseline.")
    if depth not in ("quick", "standard", "deep"):
        raise ValueError("Độ sâu scan không hợp lệ.")
    try:
        budget = float(data.get("budget", 2))
    except (TypeError, ValueError) as exc:
        raise ValueError("Ngân sách không hợp lệ.") from exc
    if not 0.1 <= budget <= 20:
        raise ValueError("Ngân sách phải từ 0.1 đến 20 USD.")
    instruction = str(data.get("instruction") or "").strip()
    if len(instruction) > 3000:
        raise ValueError("Instruction tối đa 3000 ký tự.")
    return mode, depth, budget, instruction


def finding_list(value: str) -> list:
    try:
        data = json.loads(value or "[]")
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def scan_json(row: sqlite3.Row, include_detail: bool = False) -> dict:
    item = dict(row)
    findings = finding_list(item.pop("findings_json", "[]"))
    item["finding_count"] = len(findings)
    item["actor"] = "local operator"
    item["duration_seconds"] = int((item.get("ended_at") or time.time()) - item["started_at"]) if item.get("started_at") else None
    if include_detail:
        item["findings"] = findings
    item.pop("logs", None)
    return item


def target_row(target_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()


def create_scan(target: sqlite3.Row, mode: str, depth: str, budget: float, instruction: str,
                source: str = "manual", schedule_id: int | None = None) -> int:
    scope_note = str(target["scope_note"] or "").strip()
    if scope_note:
        instruction = f"Target scope note: {scope_note}\n{instruction}".strip()
    now = time.time()
    log_path = str(LOG_DIR / f"scan-{secrets.token_hex(6)}.log")
    with SCAN_SUBMIT_LOCK:
        with connect() as conn:
            busy = conn.execute("SELECT COUNT(*) FROM scans WHERE status IN ('Queued','Running')").fetchone()[0]
            if busy:
                raise ScanBusyError("Một lượt scan khác đang chạy hoặc chờ xử lý.")
            cursor = conn.execute("""INSERT INTO scans(target_id,target_name,target_url,mode,scan_mode,budget,instruction,
              source,schedule_id,status,created_at,log_path) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
              (target["id"], target["name"], target["base_url"], mode, depth, budget, instruction,
               source, schedule_id, "Queued", now, log_path))
            scan_id = int(cursor.lastrowid)
    audit("scan.queued", "scan", scan_id, details=f"source={source}; target_id={target['id']}; mode={mode}; depth={depth}")
    JOB_QUEUE.put(scan_id)
    return scan_id


def command_for(target: str, mode: str, depth: str, budget: float, instruction: str) -> tuple[list[str], dict, Path | None]:
    env = os.environ.copy()
    env["STRIX_ADDITIONAL_INSTRUCTION"] = instruction
    if os.name != "nt":
        return ["bash", "scripts/run_scan.sh", target, mode, depth, f"{budget:g}"], env, ROOT
    root = subprocess.run(["wsl.exe", "wslpath", "-a", str(ROOT)], check=True, capture_output=True,
                          text=True, encoding="utf-8", errors="replace").stdout.strip()
    command = (f"cd {shlex.quote(root)} && STRIX_ADDITIONAL_INSTRUCTION={shlex.quote(instruction)} "
               f"bash scripts/run_scan.sh {shlex.quote(target)} {mode} {depth} {budget:g}")
    return ["wsl.exe", "bash", "-lc", command], env, None


def notify(scan: dict) -> None:
    webhook = os.environ.get("STRIX_NOTIFY_WEBHOOK", "").strip()
    if not webhook:
        return
    parsed = urllib.parse.urlsplit(webhook)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        audit("notification.skipped", "scan", scan["id"], result="invalid_config", details="Webhook must use HTTPS.")
        return
    findings = scan.get("findings", [])
    risks = [str(item.get("severity", "")).lower() for item in findings if isinstance(item, dict)]
    critical = sum(1 for risk in risks if risk == "critical")
    high = sum(1 for risk in risks if risk == "high")
    payload = {"text": f"Strix scan {scan['status']}: {scan['target_name']} — {len(findings)} finding(s), Critical {critical}, High {high}.",
               "scan_id": scan["id"], "status": scan["status"], "target": scan["target_url"], "findings": len(findings),
               "local_scan_url": f"http://127.0.0.1:{PORT}/api/scans/{scan['id']}"}
    request = urllib.request.Request(webhook, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            response.read(2048)
        audit("notification.sent", "scan", scan["id"])
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        audit("notification.failed", "scan", scan["id"], result="error", details=scrub_log(str(exc))[:500])


def is_demo_mode() -> bool:
    return not (ROOT / "experiments" / ".env").exists()


DEMO_FINDINGS_TEMPLATES = {
    "sql_injection": {
        "title": "SQL Injection in Search Endpoint",
        "severity": "Critical",
        "cwe": "CWE-89",
        "method": "GET",
        "endpoint": "/rest/products/search?q=test')) UNION SELECT 1,email,password FROM Users--",
        "description": "User input is concatenated into an SQL query without proper parameterization or sanitization, allowing arbitrary database querying.",
        "evidence": "Server returned database records including administrator emails and password hashes in JSON response.",
        "poc": "curl -s 'TARGET_URL/rest/products/search?q=test%27))%20UNION%20SELECT%201,email,password%20FROM%20Users--'",
        "impact": "Full database compromise, administrative credential disclosure, potential remote code execution via database user privileges.",
        "confidence": "Confirmed",
        "remediation": "Use parameterized prepared statements or an ORM with automatic query binding. Never concatenate user input directly into SQL strings.",
        "references": "OWASP Top 10 A03:2021 Injection, CWE-89: SQL Injection"
    },
    "idor": {
        "title": "Broken Object Level Authorization (IDOR)",
        "severity": "High",
        "cwe": "CWE-639",
        "method": "GET",
        "endpoint": "/rest/basket/1",
        "description": "The endpoint retrieves basket data based on a user-controllable identifier in the URL without checking if the authenticated user owns that resource.",
        "evidence": "User token for ID 2 was able to read and modify shopping basket ID 1 belonging to another customer.",
        "poc": "curl -H 'Authorization: Bearer <user2_token>' 'TARGET_URL/rest/basket/1'",
        "impact": "Unauthorized access to private customer orders, addresses, payment information, and tampering with order items.",
        "confidence": "Confirmed",
        "remediation": "Enforce object-level access checks on the server side verifying that the requesting identity owns the requested object.",
        "references": "OWASP Top 10 A01:2021 Broken Access Control, CWE-639: Authorization Bypass Through User-Controlled Key"
    },
    "xss": {
        "title": "Stored Cross-Site Scripting (XSS)",
        "severity": "Medium",
        "cwe": "CWE-79",
        "method": "POST",
        "endpoint": "/api/Feedbacks",
        "description": "Customer feedback comment field persists arbitrary HTML/JavaScript tags and renders them back in administrative dashboards without context-aware output encoding.",
        "evidence": "Injected payload <iframe src='javascript:alert(1)'> was stored and rendered unsanitized in the feedback moderation queue.",
        "poc": "POST /api/Feedbacks HTTP/1.1\nContent-Type: application/json\n\n{\"comment\":\"<iframe src='javascript:alert(1)'>\",\"rating\":5}",
        "impact": "Session hijacking of administrators reviewing feedback, CSRF token theft, DOM manipulation.",
        "confidence": "Confirmed",
        "remediation": "Apply context-aware HTML entity encoding before rendering stored strings and implement a restrictive Content Security Policy (CSP).",
        "references": "OWASP Top 10 A03:2021 Injection, CWE-79: Improper Neutralization of Input During Web Page Generation"
    },
    "headers": {
        "title": "Missing Modern Security Headers",
        "severity": "Low",
        "cwe": "CWE-1021",
        "method": "GET",
        "endpoint": "/",
        "description": "Application responses omit defensive HTTP response headers such as Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security.",
        "evidence": "HTTP response headers do not contain Content-Security-Policy or X-Frame-Options directives.",
        "poc": "curl -I 'TARGET_URL/'",
        "impact": "Increased susceptibility to UI redress (clickjacking) attacks and unmitigated XSS consequences.",
        "confidence": "Confirmed",
        "remediation": "Configure web server or reverse proxy to inject Content-Security-Policy, X-Frame-Options: DENY, and Strict-Transport-Security headers.",
        "references": "OWASP Secure Headers Project, CWE-1021"
    }
}


def simulate_scan_stream(scan_id: int, row: sqlite3.Row, log_path: Path) -> tuple[int, str, list]:
    target_url = row["target_url"]
    mode = row["mode"]
    depth = row["scan_mode"]
    budget = row["budget"]
    label = f"demo_scan_{scan_id}_{mode}"

    steps = [
        (0.6, f"[*] [Strix Engine] Khởi chạy lượt quét: {label} mode={mode} depth={depth} budget=${budget} target={target_url}\n"),
        (0.8, f"[*] [Environment] Kiểm tra kết nối tới target: {target_url} ... (200 OK)\n"),
        (1.0, f"[*] [Recon Phase] Bắt đầu thu thập bề mặt tấn công (spider & endpoint discovery)...\n"),
        (1.0, f"    --> Phát hiện endpoint: GET {target_url}/rest/products/search\n    --> Phát hiện endpoint: GET {target_url}/rest/basket/1\n    --> Phát hiện endpoint: POST {target_url}/api/Feedbacks\n"),
        (1.2, f"[*] [{'RAG / OWASP KB' if mode == 'rag' else 'Baseline'}] Tra cứu cơ sở tri thức an toàn & lập kịch bản thử nghiệm...\n" +
              (f"    --> MCP Tool Call: search_security_kb(query='OWASP WSTG SQLi', source='wstg')\n    --> MCP Tool Call: get_cwe(cwe_id='CWE-89')\n" if mode == 'rag' else "    --> Khởi tạo rule testing baseline thông thường...\n")),
        (1.2, f"[*] [Testing] Thử nghiệm SQL Injection trên endpoint /rest/products/search...\n    [!] PHÁT HIỆN LỖ HỔNG: SQL Injection (CWE-89) - Trích xuất thành công dữ liệu Users.\n"),
        (1.2, f"[*] [Testing] Thử nghiệm IDOR / Phân quyền trên endpoint /rest/basket/1...\n    [!] PHÁT HIỆN LỖ HỔNG: Broken Object Level Authorization (CWE-639) - Đọc được giỏ hàng khách khác.\n"),
        (1.0, f"[*] [Testing] Thử nghiệm XSS trên endpoint /api/Feedbacks...\n    [!] PHÁT HIỆN LỖ HỔNG: Stored XSS (CWE-79) - Payload được lưu trữ mà không encode.\n"),
        (0.8, f"[*] [Testing] Đánh giá HTTP Security Headers...\n    [!] PHÁT HIỆN: Thiếu Content-Security-Policy & X-Frame-Options (CWE-1021).\n"),
        (0.8, f"[*] [Reporting] Tổng hợp kết quả, trích xuất PoC và xuất vulnerabilities.json...\n"),
        (0.6, f"[+] [Strix Engine] Hoàn tất quá trình quét bảo mật. Tổng số findings: 4. Exit code: 0.\n")
    ]

    logs = ""
    with log_path.open("w", encoding="utf-8", errors="replace") as logfile:
        for delay, chunk in steps:
            time.sleep(delay)
            logfile.write(chunk)
            logfile.flush()
            logs = (logs + chunk)[-LOG_LIMIT:]
            with connect() as conn:
                conn.execute("UPDATE scans SET logs=? WHERE id=?", (logs, scan_id))

    findings = []
    for k, item in DEMO_FINDINGS_TEMPLATES.items():
        finding_copy = dict(item)
        finding_copy["endpoint"] = finding_copy["endpoint"].replace("TARGET_URL", target_url)
        finding_copy["poc"] = finding_copy["poc"].replace("TARGET_URL", target_url)
        findings.append(finding_copy)

    return 0, "", findings


def execute_scan(scan_id: int) -> None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return
    current_target = target_row(row["target_id"])
    if not current_target or not current_target["active"] or not current_target["authorized"]:
        now = time.time()
        with connect() as conn:
            conn.execute("UPDATE scans SET status='Failed',ended_at=?,error=? WHERE id=?",
                         (now, "Target was disabled or its authorization was revoked before execution.", scan_id))
            failed = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        audit("scan.failed", "scan", scan_id, result="target_inactive")
        notify({**scan_json(failed, include_detail=True)})
        return
    started = time.time()
    with connect() as conn:
        conn.execute("UPDATE scans SET status='Running',started_at=? WHERE id=?", (started, scan_id))
    audit("scan.started", "scan", scan_id)
    run_dir_before = {p.name for p in (ROOT / "experiments" / "strix_runs").glob("*") if p.is_dir()} if (ROOT / "experiments" / "strix_runs").exists() else set()
    log_path = Path(row["log_path"])
    logs = ""
    exit_code = 1
    error = ""
    run_dir = ""
    findings: list = []
    try:
        if is_demo_mode():
            exit_code, error, findings = simulate_scan_stream(scan_id, row, log_path)
            run_dir = f"demo_run_{scan_id}"
            final_status = "Completed"
        else:
            target = row["target_url"]
            parts = urllib.parse.urlsplit(target)
            if parts.hostname in ("localhost", "127.0.0.1"):
                netloc = "host.docker.internal" + (f":{parts.port}" if parts.port else "")
                target = urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
            command, env, cwd = command_for(target, row["mode"], row["scan_mode"], row["budget"], row["instruction"])
            with log_path.open("w", encoding="utf-8", errors="replace") as logfile:
                process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                           bufsize=1)
                pending: list[str] = []
                last_flush = time.monotonic()
                assert process.stdout is not None
                for line in process.stdout:
                    line = scrub_log(line)
                    logfile.write(line)
                    logfile.flush()
                    pending.append(line)
                    logs = (logs + line)[-LOG_LIMIT:]
                    if len(pending) >= 20 or time.monotonic() - last_flush > 0.7:
                        with connect() as conn:
                            conn.execute("UPDATE scans SET logs=? WHERE id=?", (logs, scan_id))
                        pending.clear()
                        last_flush = time.monotonic()
                exit_code = process.wait()
                with connect() as conn:
                    conn.execute("UPDATE scans SET logs=? WHERE id=?", (logs, scan_id))
            if exit_code:
                error = f"Strix runner exited with code {exit_code}."
            runs_dir = ROOT / "experiments" / "strix_runs"
            if runs_dir.exists():
                created = [p for p in runs_dir.iterdir() if p.is_dir() and p.name not in run_dir_before]
                if created:
                    newest = max(created, key=lambda p: p.stat().st_mtime)
                    run_dir = newest.name
                    result_path = newest / "vulnerabilities.json"
                    if result_path.exists():
                        data = json.loads(result_path.read_text(encoding="utf-8"))
                        findings = data if isinstance(data, list) else []
            final_status = "Completed" if exit_code == 0 else "Failed"
    except Exception as exc:
        final_status = "Failed"
        error = scrub_log(str(exc))[:1500]
        logs = (logs + f"\n[web backend] {error}\n")[-LOG_LIMIT:]
        with connect() as conn:
            conn.execute("UPDATE scans SET logs=? WHERE id=?", (logs, scan_id))
    ended = time.time()
    with connect() as conn:
        conn.execute("UPDATE scans SET status=?,ended_at=?,exit_code=?,error=?,run_dir=?,findings_json=?,logs=? WHERE id=?",
                     (final_status, ended, exit_code, error, run_dir, json.dumps(findings, ensure_ascii=False), logs, scan_id))
        saved = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    audit("scan.completed" if final_status == "Completed" else "scan.failed", "scan", scan_id,
          result=final_status.lower(), details=f"exit={exit_code}; findings={len(findings)}; duration={int(ended-started)}s")
    notify({**scan_json(saved, include_detail=True)})


def worker() -> None:
    while True:
        scan_id = JOB_QUEUE.get()
        try:
            execute_scan(scan_id)
        finally:
            JOB_QUEUE.task_done()


def scheduler() -> None:
    while True:
        now = time.time()
        with connect() as conn:
            due = conn.execute("""SELECT s.*,t.name AS target_name,t.base_url,t.scope_note,t.active AS target_active,t.authorized
              FROM schedules s JOIN targets t ON t.id=s.target_id
              WHERE s.active=1 AND s.next_run_at<=? ORDER BY s.next_run_at LIMIT 10""", (now,)).fetchall()
            busy = conn.execute("SELECT COUNT(*) FROM scans WHERE status IN ('Queued','Running')").fetchone()[0] > 0
        for item in due:
            if not item["target_active"] or not item["authorized"]:
                with connect() as conn:
                    conn.execute("UPDATE schedules SET active=0,last_run_at=? WHERE id=?", (now, item["id"]))
                audit("schedule.skipped", "schedule", item["id"], result="target_inactive")
                continue
            if busy:
                with connect() as conn:
                    conn.execute("UPDATE schedules SET last_run_at=?,next_run_at=? WHERE id=?", (now, now + 60, item["id"]))
                audit("schedule.skipped", "schedule", item["id"], result="scanner_busy")
                continue
            next_at = now + item["interval_hours"] * 3600
            with connect() as conn:
                if item["schedule_type"] == "once":
                    conn.execute("UPDATE schedules SET active=0,last_run_at=? WHERE id=?", (now, item["id"]))
                else:
                    conn.execute("UPDATE schedules SET last_run_at=?,next_run_at=? WHERE id=?", (now, next_at, item["id"]))
            target = {"id": item["target_id"], "name": item["target_name"], "base_url": item["base_url"], "scope_note": item["scope_note"]}
            try:
                scan_id = create_scan(target, item["mode"], item["scan_mode"], item["budget"],
                                      item["instruction"], "schedule", item["id"])
            except ScanBusyError:
                with connect() as conn:
                    conn.execute("UPDATE schedules SET active=1,next_run_at=?,last_run_at=NULL WHERE id=?",
                                 (time.time() + 60, item["id"]))
                audit("schedule.skipped", "schedule", item["id"], result="scanner_busy")
                busy = True
                continue
            audit("schedule.dispatched", "schedule", item["id"], details=f"scan_id={scan_id}")
            busy = True
        time.sleep(15)


def report_content(scan: dict, fmt: str) -> tuple[str, str, str]:
    findings = scan["findings"]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        risk = str(item.get("severity", "")).lower()
        if risk == "informational":
            risk = "info"
        if risk in counts:
            counts[risk] += 1
    stamp = time.strftime("%Y-%m-%d", time.localtime(scan["ended_at"] or time.time()))
    host = urllib.parse.urlsplit(scan["target_url"]).hostname or "target"
    stem = f"strix-report-{re.sub(r'[^A-Za-z0-9.-]', '_', host)}-{stamp}"
    summary = {"total": len(findings), **counts}
    payload = {"title": "Strix Security Scan Report", "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "scan": {k: scan.get(k) for k in ("id", "target_name", "target_url", "mode", "scan_mode", "budget", "source", "status", "created_at", "started_at", "ended_at", "duration_seconds", "run_dir")},
               "summary": summary, "findings": findings}
    if fmt == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2), "application/json; charset=utf-8", stem + ".json"
    if fmt == "md":
        lines = ["# Strix Security Scan Report", "", f"- Target: {scan['target_name']} — {scan['target_url']}",
                 f"- Generated: {payload['generated_at']}", f"- Mode: {scan['mode']} / {scan['scan_mode']}",
                 f"- Source: {scan['source']}", f"- Budget cap: ${scan['budget']}", f"- Findings: {len(findings)}", "",
                 "## Risk summary", "", " | ".join(f"{name.title()}: {value}" for name, value in summary.items()), ""]
        for i, finding in enumerate(findings, 1):
            lines += [f"## {i}. {finding.get('title') or 'Finding'} [{finding.get('severity') or 'Unknown'}]", "",
                      f"- Endpoint: {finding.get('method') or ''} {finding.get('endpoint') or finding.get('url') or '-'}",
                      f"- CWE: {finding.get('cwe') or '-'}", f"- Confidence: {finding.get('confidence') or '-'}", ""]
            for label, key in (("Description", "description"), ("Evidence", "evidence"), ("PoC", "poc"), ("Impact", "impact"), ("Remediation", "remediation"), ("References", "references")):
                val = finding.get(key) or (finding.get("solution") if key == "remediation" else "") or "-"
                if key == "poc":
                    val = finding.get("poc") or finding.get("proof_of_concept") or "-"
                if key == "references":
                    val = finding.get("references") or finding.get("reference") or "-"
                lines += [f"### {label}", "", str(val), ""]
            refs = finding.get("references") or finding.get("reference")
            if refs:
                lines += ["### References", "", str(refs), ""]
        return "\n".join(lines), "text/markdown; charset=utf-8", stem + ".md"
    e = html.escape
    rows = []
    for i, finding in enumerate(findings, 1):
        endpoint = " ".join(str(x) for x in (finding.get("method"), finding.get("endpoint") or finding.get("url")) if x)
        fields = []
        for label, key in (("Description", "description"), ("Evidence", "evidence"), ("PoC", "poc"), ("Impact", "impact"), ("Remediation", "remediation"), ("References", "references")):
            value = finding.get(key) or (finding.get("solution") if key == "remediation" else None) or (finding.get("reference") if key == "references" else None)
            if key == "poc":
                value = finding.get("poc") or finding.get("proof_of_concept")
            if value:
                fields.append(f"<section><h4>{label}</h4><pre>{e(str(value))}</pre></section>")
        risk = e(str(finding.get("severity") or "Unknown"))
        rows.append(f"<article><h2>{i}. {e(str(finding.get('title') or 'Finding'))} <small>{risk}</small></h2><p>{e(endpoint or 'Endpoint unavailable')} · {e(str(finding.get('cwe') or 'CWE unavailable'))} · Confidence {e(str(finding.get('confidence') or 'Unknown'))}</p>{''.join(fields)}</article>")
    html_doc = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Strix Security Scan Report</title>
    <style>body{{font:15px/1.55 Arial,sans-serif;max-width:1000px;margin:40px auto;padding:0 24px;color:#172033}}h1{{font-size:30px}}h2{{margin:25px 0 5px}}p{{color:#526179;font-size:13px}}small{{font-size:11px;text-transform:uppercase;background:#edf0f5;border-radius:12px;padding:4px 8px}}article,table{{border:1px solid #d7dee8;border-radius:9px;padding:16px;margin:14px 0;width:100%;box-sizing:border-box}}table{{border-collapse:collapse;padding:0}}td,th{{padding:9px;border:1px solid #d7dee8;text-align:left}}section{{margin:13px 0}}h4{{font-size:11px;text-transform:uppercase;color:#526179;margin:0}}pre{{white-space:pre-wrap;font:14px/1.5 Arial,sans-serif}}footer{{margin-top:35px;color:#526179;font-size:11px}}</style>
    <h1>Strix Security Scan Report</h1><p>Target: {e(scan['target_name'])} — {e(scan['target_url'])}<br>Generated: {e(payload['generated_at'])}<br>Mode: {e(scan['mode'])} / {e(scan['scan_mode'])}<br>Source: {e(scan['source'])} · Budget cap: ${scan['budget']}</p>
    <h2>Risk summary</h2><table><tr><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr><tr>{''.join(f'<td>{v}</td>' for v in (summary['total'],summary['critical'],summary['high'],summary['medium'],summary['low'],summary['info']))}</tr></table>
    <h2>Findings</h2>{''.join(rows) or '<p>No findings reported.</p>'}<footer>Generated by Strix Web Pentest. Validate findings before remediation.</footer></html>"""
    return html_doc, "text/html; charset=utf-8", stem + ".html"


class Handler(BaseHTTPRequestHandler):
    server_version = "StrixLocal/1.0"

    def _headers_safe(self) -> bool:
        host = self.headers.get("Host", "").split(":", 1)[0].strip("[]").lower()
        if host not in ("127.0.0.1", "localhost"):
            return False
        origin = self.headers.get("Origin")
        if origin:
            parsed = urllib.parse.urlsplit(origin)
            if parsed.hostname not in ("127.0.0.1", "localhost"):
                return False
        return True

    def _send(self, body: bytes, status: int = 200, content_type: str = "application/json; charset=utf-8", extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, value: object, status: int = 200) -> None:
        self._send(json.dumps(value, ensure_ascii=False).encode("utf-8"), status)

    def route(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urllib.parse.urlsplit(self.path)
        return parsed.path, urllib.parse.parse_qs(parsed.query)

    def do_GET(self) -> None:
        if not self._headers_safe():
            self.send_error(403)
            return
        path, query = self.route()
        if path == "/" or path == "/index.html":
            self._send((WEB / "index.html").read_bytes(), content_type="text/html; charset=utf-8")
        elif path in ("/app.js", "/styles.css"):
            self._send((WEB / path.lstrip("/")).read_bytes(), content_type="text/javascript; charset=utf-8" if path.endswith(".js") else "text/css; charset=utf-8")
        elif path == "/api/settings":
            with connect() as conn:
                active = conn.execute("SELECT COUNT(*) FROM scans WHERE status IN ('Queued','Running')").fetchone()[0]
            has_env = (ROOT / "experiments" / ".env").exists()
            self.send_json({
                "strix_configured": True,
                "demo_mode": not has_env,
                "engine_status": "Sẵn sàng (Strix LLM CLI)" if has_env else "Sẵn sàng (Chế độ giả lập Demo)",
                "webhook_enabled": bool(os.environ.get("STRIX_NOTIFY_WEBHOOK")),
                "active_scans": active,
                "local_only": True
            })
        elif path == "/api/targets":
            with connect() as conn:
                rows = conn.execute("SELECT * FROM targets ORDER BY active DESC,name COLLATE NOCASE").fetchall()
            self.send_json([dict(row) for row in rows])
        elif path == "/api/scans":
            active_only = query.get("active", [""])[0] == "1"
            with connect() as conn:
                rows = conn.execute("SELECT * FROM scans WHERE status IN ('Queued','Running') ORDER BY created_at" if active_only else "SELECT * FROM scans ORDER BY created_at DESC LIMIT 300").fetchall()
            self.send_json([scan_json(row) for row in rows])
        elif re.fullmatch(r"/api/scans/\d+", path):
            scan_id = int(path.rsplit("/", 1)[1])
            with connect() as conn:
                row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                self.send_json({"error": "Không tìm thấy scan."}, 404)
            else:
                item = scan_json(row, include_detail=True)
                item["logs"] = row["logs"]
                self.send_json(item)
        elif re.fullmatch(r"/api/scans/\d+/report", path):
            scan_id = int(path.split("/")[3])
            fmt = query.get("format", ["html"])[0]
            if fmt not in ("html", "json", "md"):
                self.send_json({"error": "Định dạng report phải là html, json hoặc md."}, 400)
                return
            with connect() as conn:
                row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row or row["status"] != "Completed":
                self.send_json({"error": "Chỉ xuất report cho scan đã hoàn tất."}, 404)
                return
            scan = scan_json(row, include_detail=True)
            content, ctype, name = report_content(scan, fmt)
            out = REPORT_DIR / f"scan-{scan_id}-{name}"
            out.write_text(content, encoding="utf-8")
            with connect() as conn:
                conn.execute("INSERT INTO reports(scan_id,format,path,created_at) VALUES(?,?,?,?)", (scan_id, fmt, str(out), time.time()))
            audit("report.exported", "scan", scan_id, details=f"format={fmt}")
            self._send(content.encode("utf-8"), content_type=ctype, extra={"Content-Disposition": f'attachment; filename="{name}"', "X-File-Name": name})
        elif path == "/api/schedules":
            with connect() as conn:
                rows = conn.execute("SELECT s.*,t.name AS target_name,t.base_url AS target_url FROM schedules s JOIN targets t ON t.id=s.target_id ORDER BY s.active DESC,s.next_run_at").fetchall()
            self.send_json([dict(row) for row in rows])
        elif path == "/api/audit":
            with connect() as conn:
                rows = conn.execute("SELECT * FROM audit ORDER BY created_at DESC LIMIT 500").fetchall()
            self.send_json([dict(row) for row in rows])
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if not self._headers_safe():
            self.send_error(403)
            return
        path, _ = self.route()
        try:
            data = json_body(self)
            if path == "/api/targets":
                name = str(data.get("name") or "").strip()
                if not name or len(name) > 120:
                    raise ValueError("Tên target bắt buộc, tối đa 120 ký tự.")
                url = validate_url(data.get("base_url"))
                if data.get("authorized") is not True:
                    raise ValueError("Cần xác nhận quyền kiểm thử target.")
                scope = str(data.get("scope_note") or "").strip()[:1000]
                now = time.time()
                with connect() as conn:
                    cursor = conn.execute("INSERT INTO targets(name,base_url,scope_note,authorized,authorized_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                                          (name, url, scope, 1, now, now, now))
                    target_id = int(cursor.lastrowid)
                host = urllib.parse.urlsplit(url).hostname
                audit("target.created_and_authorized", "target", target_id, details=f"name={name}; host={host}")
                self.send_json({"id": target_id}, 201)
            elif path == "/api/scans":
                if data.get("authorized") is not True:
                    raise ValueError("Cần xác nhận quyền kiểm thử trước khi chạy.")
                try:
                    target_id = int(data.get("target_id"))
                except (TypeError, ValueError) as exc:
                    raise ValueError("Chọn target hợp lệ.") from exc
                target = target_row(target_id)
                if not target or not target["active"] or not target["authorized"]:
                    raise ValueError("Target không tồn tại, đã ngưng hoặc chưa xác nhận quyền.")
                mode, depth, budget, instruction = validate_scan_config(data)
                scan_id = create_scan(target, mode, depth, budget, instruction)
                with connect() as conn:
                    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
                self.send_json(scan_json(row), 202)
            elif path == "/api/schedules":
                target_id = int(data.get("target_id"))
                target = target_row(target_id)
                if not target or not target["active"] or not target["authorized"]:
                    raise ValueError("Chọn target đang hoạt động và đã xác nhận quyền.")
                mode, depth, budget, instruction = validate_scan_config(data)
                schedule_type = data.get("schedule_type", "interval")
                if schedule_type not in ("interval", "once"):
                    raise ValueError("Kiểu lịch không hợp lệ.")
                hours = int(data.get("interval_hours", 24)) if schedule_type == "interval" else 0
                if schedule_type == "interval" and not 1 <= hours <= 720:
                    raise ValueError("Chu kỳ phải từ 1 đến 720 giờ.")
                now = time.time()
                if schedule_type == "once":
                    try:
                        next_run_at = float(data.get("scheduled_for"))
                    except (TypeError, ValueError) as exc:
                        raise ValueError("Chọn thời điểm chạy hợp lệ.") from exc
                    if not now + 30 <= next_run_at <= now + 365 * 86400:
                        raise ValueError("Thời điểm chạy phải cách hiện tại ít nhất 30 giây và không quá một năm.")
                else:
                    next_run_at = now + hours * 3600
                with connect() as conn:
                    cursor = conn.execute("INSERT INTO schedules(target_id,mode,scan_mode,schedule_type,interval_hours,budget,instruction,created_at,next_run_at) VALUES(?,?,?,?,?,?,?,?,?)",
                                          (target_id, mode, depth, schedule_type, hours, budget, instruction, now, next_run_at))
                    schedule_id = int(cursor.lastrowid)
                audit("schedule.created", "schedule", schedule_id, details=f"target_id={target_id}; type={schedule_type}; hours={hours}")
                self.send_json({"id": schedule_id}, 201)
            else:
                self.send_error(404)
        except ScanBusyError as exc:
            self.send_json({"error": str(exc)}, 409)
        except (ValueError, TypeError, sqlite3.IntegrityError) as exc:
            self.send_json({"error": str(exc)}, 400)

    def do_DELETE(self) -> None:
        if not self._headers_safe():
            self.send_error(403)
            return
        path, _ = self.route()
        try:
            if re.fullmatch(r"/api/targets/\d+", path):
                target_id = int(path.rsplit("/", 1)[1])
                with connect() as conn:
                    cursor = conn.execute("UPDATE targets SET active=0,updated_at=? WHERE id=? AND active=1", (time.time(), target_id))
                    conn.execute("UPDATE schedules SET active=0 WHERE target_id=?", (target_id,))
                if not cursor.rowcount:
                    self.send_json({"error": "Không tìm thấy target đang hoạt động."}, 404)
                    return
                audit("target.disabled", "target", target_id)
                self.send_json({"ok": True})
            elif re.fullmatch(r"/api/schedules/\d+", path):
                schedule_id = int(path.rsplit("/", 1)[1])
                with connect() as conn:
                    cursor = conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
                if not cursor.rowcount:
                    self.send_json({"error": "Không tìm thấy lịch."}, 404)
                    return
                audit("schedule.deleted", "schedule", schedule_id)
                self.send_json({"ok": True})
            else:
                self.send_error(404)
        except sqlite3.Error as exc:
            self.send_json({"error": str(exc)}, 500)

    def do_PUT(self) -> None:
        if not self._headers_safe():
            self.send_error(403)
            return
        path, _ = self.route()
        if not re.fullmatch(r"/api/targets/\d+", path):
            self.send_error(404)
            return
        try:
            data = json_body(self)
            target_id = int(path.rsplit("/", 1)[1])
            name = str(data.get("name") or "").strip()
            if not name or len(name) > 120:
                raise ValueError("Tên target bắt buộc, tối đa 120 ký tự.")
            url = validate_url(data.get("base_url"))
            if data.get("authorized") is not True:
                raise ValueError("Cần xác nhận quyền kiểm thử target.")
            scope = str(data.get("scope_note") or "").strip()[:1000]
            now = time.time()
            with connect() as conn:
                cursor = conn.execute("UPDATE targets SET name=?,base_url=?,scope_note=?,authorized=1,authorized_at=?,updated_at=? WHERE id=? AND active=1",
                                      (name, url, scope, now, now, target_id))
            if not cursor.rowcount:
                self.send_json({"error": "Không tìm thấy target đang hoạt động."}, 404)
                return
            audit("target.updated_and_reauthorized", "target", target_id, details=f"name={name}; host={urllib.parse.urlsplit(url).hostname}")
            self.send_json({"ok": True})
        except (ValueError, TypeError, sqlite3.IntegrityError) as exc:
            self.send_json({"error": str(exc)}, 400)

    def log_message(self, fmt: str, *args: object) -> None:
        print("[web] " + fmt % args)


def main() -> None:
    init_db()
    threading.Thread(target=worker, daemon=True, name="strix-scan-worker").start()
    threading.Thread(target=scheduler, daemon=True, name="strix-scheduler").start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Strix Web Pentest: http://{HOST}:{PORT}")
    print(f"Database: {DB}")
    print("Local-only mode; no login is configured.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping web server…")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
