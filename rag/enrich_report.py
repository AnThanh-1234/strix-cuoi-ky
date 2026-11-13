"""Hau xu ly bao cao Strix bang RAG (Muc 1 - khong can sua Strix).

Doc  strix_runs/<run>/vulnerabilities.json
Voi moi finding:
  1. Tao truy van tu title + CWE + mo ta
  2. Truy xuat: Cheat Sheet (khac phuc) + WSTG (cach kiem chung) + CWE chinh xac
  3. Goi LLM viet phan tich tieng Viet CO TRICH DAN [S#]  (bo qua neu --no-llm)
Ghi ra:
  <run>/enriched_report.md    bao cao bo sung
  <run>/enriched.json         du lieu tho (nguon truy xuat, token, chi phi) cho thuc nghiem

Vi du:
  python rag/enrich_report.py experiments/strix_runs/<run>
  python rag/enrich_report.py experiments/strix_runs/<run> --no-llm   # chi gan tai lieu tham chieu, $0
  python rag/enrich_report.py <run> --model ollama/qwen2.5:7b         # dung model nho local
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kb import format_results, load_kb  # noqa: E402
from taxonomy import parse_cwe, types_for_cwe  # noqa: E402

SYSTEM_PROMPT = """Ban la chuyen gia bao mat ung dung web. Nhiem vu: phan tich 1 lo hong do cong cu
pentest tu dong (Strix) phat hien, DUA TREN tai lieu tham chieu duoc cung cap.
Quy tac:
- Chi khang dinh dieu co trong tai lieu tham chieu hoac bang chung cua finding; trich dan bang [S#].
- Neu tai lieu khong du, noi ro "tai lieu tham chieu khong de cap".
- Danh gia xem finding co dau hieu false positive khong (dua tren evidence).
- Viet bang tieng Viet, ngan gon, dung thuat ngu chuan (giu nguyen thuat ngu tieng Anh khi can)."""

USER_TEMPLATE = """## Finding tu Strix
Title: {title}
Severity: {severity} | CWE: {cwe} | Endpoint: {method} {endpoint}
Description: {description}
Evidence: {evidence}
Impact: {impact}

## Tai lieu tham chieu (OWASP Cheat Sheets / WSTG / MITRE CWE)
{context}

## Yeu cau - tra loi dung cac muc sau (Markdown):
### 1. Ban chat lo hong
### 2. Nguyen nhan goc (root cause)
### 3. Danh gia anh huong & do tin cay finding (co dau hieu false positive khong?)
### 4. Bien phap khac phuc (cu the, co trich dan [S#])
### 5. Cach kiem chung lai sau khi sua (theo WSTG)
### 6. Phan loai: CWE de xuat, OWASP Top 10 2021"""


def clip(v, n=1500) -> str:
    s = "" if v is None else str(v)
    return s if len(s) <= n else s[:n] + " ..."


def retrieve_for(finding: dict) -> list[dict]:
    kb = load_kb()
    cwe_num = parse_cwe(finding.get("cwe"))
    vtype = (types_for_cwe(cwe_num) or [None])[0] if cwe_num else None
    q = " ".join(filter(None, [finding.get("title"), finding.get("cwe"), clip(finding.get("description"), 400)]))

    picked: list[dict] = []
    seen: set[str] = set()

    def add(items):
        for it in items:
            if it["id"] not in seen:
                seen.add(it["id"])
                picked.append(it)

    if cwe_num:
        add(kb.get_cwe(cwe_num)[:2])
    add(kb.search(q, top_k=3, source="cheatsheet", vuln_type=vtype))
    add(kb.search(q, top_k=2, source="wstg", vuln_type=vtype))
    if not cwe_num:
        add(kb.search(q, top_k=1, source="cwe"))
    return picked


def call_llm(model: str, prompt: str) -> tuple[str, dict]:
    import litellm

    kwargs = {}
    if os.environ.get("LLM_API_KEY"):
        kwargs["api_key"] = os.environ["LLM_API_KEY"]
    if os.environ.get("LLM_API_BASE"):
        kwargs["api_base"] = os.environ["LLM_API_BASE"]
    t0 = time.time()
    resp = litellm.completion(
        model=model,
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=1800,
        **kwargs,
    )
    try:
        cost = litellm.completion_cost(completion_response=resp)
    except Exception:
        cost = None
    u = resp.usage
    return resp.choices[0].message.content, {
        "model": model,
        "input_tokens": u.prompt_tokens,
        "output_tokens": u.completion_tokens,
        "cost_usd": cost,
        "seconds": round(time.time() - t0, 1),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--model", default=os.environ.get("STRIX_LLM"))
    ap.add_argument("--no-llm", action="store_true", help="chi truy xuat tai lieu, khong goi LLM")
    args = ap.parse_args()

    vuln_path = args.run_dir / "vulnerabilities.json"
    if not vuln_path.exists():
        sys.exit(f"Khong thay {vuln_path}")
    findings = json.loads(vuln_path.read_text(encoding="utf-8"))
    if not findings:
        sys.exit("Run khong co finding nao.")
    if not args.no_llm and not args.model:
        sys.exit("Can --model hoac bien STRIX_LLM (hoac dung --no-llm).")

    md = [f"# Bao cao bo sung bang RAG — {args.run_dir.name}\n",
          f"- So finding: {len(findings)}",
          f"- Knowledge Base: {load_kb().meta['n_chunks']} chunks ({load_kb().meta['embed_model']})",
          f"- LLM: {'(khong dung)' if args.no_llm else args.model}\n"]
    records, total_cost, total_in, total_out = [], 0.0, 0, 0

    for n, f in enumerate(findings, 1):
        print(f"[{n}/{len(findings)}] {f.get('title')}", file=sys.stderr)
        refs = retrieve_for(f)
        context = format_results(refs)
        md.append(f"\n---\n\n## {n}. {f.get('title')}  `[{str(f.get('severity', '')).upper()}]`\n")
        md.append(f"**CWE (Strix):** {f.get('cwe') or '-'} · **Endpoint:** {f.get('method') or ''} {f.get('endpoint') or '-'}\n")

        rec = {"id": f.get("id"), "title": f.get("title"), "cwe": f.get("cwe"),
               "refs": [{"tag": f"S{i}", "source": r["source"], "title": r["doc_title"], "section": r["section"],
                         "url": r["url"]} for i, r in enumerate(refs, 1)]}
        if not args.no_llm:
            prompt = USER_TEMPLATE.format(
                title=f.get("title"), severity=f.get("severity"), cwe=f.get("cwe") or "-",
                method=f.get("method") or "", endpoint=f.get("endpoint") or "-",
                description=clip(f.get("description")), evidence=clip(f.get("evidence"), 1200),
                impact=clip(f.get("impact"), 600), context=context)
            try:
                answer, usage = call_llm(args.model, prompt)
            except Exception as exc:
                answer, usage = f"> Loi goi LLM: {exc}", {"error": str(exc)}
            md.append(answer.strip() + "\n")
            rec["analysis"] = answer
            rec["usage"] = usage
            total_cost += usage.get("cost_usd") or 0.0
            total_in += usage.get("input_tokens") or 0
            total_out += usage.get("output_tokens") or 0

        md.append("**Tai lieu tham chieu:**\n")
        md += [f"- [S{i}] [{r['doc_title']} — {r['section']}]({r['url']})" for i, r in enumerate(refs, 1)]
        records.append(rec)

    if not args.no_llm:
        md.append(f"\n---\n\n**Chi phi RAG:** {total_in} input + {total_out} output tokens ≈ ${total_cost:.4f}")
    (args.run_dir / "enriched_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (args.run_dir / "enriched.json").write_text(json.dumps(
        {"model": None if args.no_llm else args.model, "input_tokens": total_in, "output_tokens": total_out,
         "cost_usd": total_cost, "findings": records}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"-> {args.run_dir / 'enriched_report.md'}", file=sys.stderr)


if __name__ == "__main__":
    main()
