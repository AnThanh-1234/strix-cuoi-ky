"""MCP server: cung cap Web Application Security Knowledge Base cho agent cua Strix.

Strix (>=1.7) doc danh sach MCP server tu file JSON (--mcp-config) va cho moi agent
goi cac tool ben duoi TRONG LUC QUET:
  - search_security_kb : tra cuu OWASP Cheat Sheets / WSTG / CWE (hybrid search)
  - get_cwe            : chi tiet 1 CWE (mo ta, hau qua, khac phuc, phat hien)
  - lookup_cve         : tra CVE moi tu NVD API (bo sung loi moi ngoai KB tinh)
  - list_vuln_types    : danh sach vuln_type dung de loc

Moi lan goi tool duoc ghi vao file log JSONL (KB_TOOL_LOG) de phan tich thuc nghiem:
agent co dung KB khong, dung bao nhieu lan, hoi gi.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

from kb import ROOT, format_results, load_kb  # noqa: E402
from taxonomy import VULN_TYPES  # noqa: E402

LOG_PATH = Path(os.environ.get("KB_TOOL_LOG", ROOT / "experiments" / "kb_tool_calls.jsonl"))
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

mcp = FastMCP("owasp_kb")


def _log(tool: str, args: dict, n_results: int, started: float) -> None:
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "run": os.environ.get("KB_RUN_LABEL") or os.environ.get("STRIX_RUN_ID"),
            "tool": tool,
            "args": args,
            "n_results": n_results,
            "ms": int((time.time() - started) * 1000),
        }
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


@mcp.tool()
def search_security_kb(
    query: str,
    source: str | None = None,
    vuln_type: str | None = None,
    top_k: int = 5,
) -> str:
    """Search the OWASP/MITRE web-security knowledge base.

    Use it (1) BEFORE testing a vulnerability class, with source="wstg", to get the
    official OWASP test procedure and payload ideas; (2) BEFORE reporting a finding,
    with source="cheatsheet", to get root cause and remediation guidance; (3) with
    source="cwe" to pick the correct CWE. Cite returned [S#] titles/URLs in reports.

    Args:
        query: natural-language question or keywords (English works best),
               e.g. "JWT none algorithm bypass test", "CWE-639", "prevent SSRF in webhook".
        source: optional filter: "cheatsheet" (defenses), "wstg" (how to test), "cwe" (weakness taxonomy).
        vuln_type: optional filter, one of list_vuln_types() (e.g. "sql_injection", "idor", "ssrf").
        top_k: number of passages (1-10).
    """
    t0 = time.time()
    top_k = max(1, min(int(top_k), 10))
    if source not in (None, "", "cheatsheet", "wstg", "cwe"):
        source = None
    if vuln_type and vuln_type not in VULN_TYPES:
        vuln_type = None
    results = load_kb().search(query, top_k=top_k, source=source or None, vuln_type=vuln_type)
    _log("search_security_kb", {"query": query, "source": source, "vuln_type": vuln_type}, len(results), t0)
    return format_results(results)


@mcp.tool()
def get_cwe(cwe_id: str) -> str:
    """Return the MITRE CWE entry (description, consequences, mitigations, detection) for an id like "CWE-89" or "89"."""
    t0 = time.time()
    chunks = load_kb().get_cwe(cwe_id)
    _log("get_cwe", {"cwe_id": cwe_id}, len(chunks), t0)
    if not chunks:
        return f"{cwe_id}: not found in local CWE catalog."
    return f"URL: {chunks[0]['url']}\n\n" + "\n\n".join(c["text"] for c in chunks)


@mcp.tool()
def lookup_cve(query: str, max_results: int = 5) -> str:
    """Look up CVEs from NVD (live). Pass a CVE id ("CVE-2024-3094") or keywords
    identifying a product/version you fingerprinted (e.g. "express 4.17 prototype pollution").
    Use this for known vulnerabilities in detected components/versions."""
    t0 = time.time()
    q = query.strip()
    params = {"cveId": q.upper()} if q.upper().startswith("CVE-") else {
        "keywordSearch": q, "resultsPerPage": max(1, min(int(max_results), 10))}
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    try:
        resp = requests.get(NVD_URL, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
    except Exception as exc:  # mang loi / bi rate-limit
        _log("lookup_cve", {"query": q}, -1, t0)
        return f"NVD lookup failed: {exc}"

    lines = []
    for it in items[:max_results]:
        cve = it["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        score = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            if metrics.get(key):
                d = metrics[key][0]["cvssData"]
                score = f"CVSS {d.get('baseScore')} {d.get('baseSeverity', '')}".strip()
                break
        cwes = sorted({x["value"] for w in cve.get("weaknesses", []) for x in w.get("description", [])})
        lines.append(f"{cve['id']} ({cve.get('published', '')[:10]}) {score} {' '.join(cwes)}\n{desc[:500]}")
    _log("lookup_cve", {"query": q}, len(lines), t0)
    return "\n\n".join(lines) if lines else f"No CVE found for '{q}'."


@mcp.tool()
def list_vuln_types() -> str:
    """List the vuln_type values accepted by search_security_kb, with related CWE and OWASP Top 10 category."""
    return "\n".join(
        f"{k}: CWE {', '.join(map(str, v['cwe'])) or '-'} | {v['top10'] or '-'}" for k, v in VULN_TYPES.items()
    )


if __name__ == "__main__":
    load_kb()  # nap truoc index + model de lan goi dau khong bi cham
    mcp.run()  # stdio transport
