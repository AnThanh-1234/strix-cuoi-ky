"""Tong hop ket qua thuc nghiem tu experiments/runs.csv -> bang so sanh baseline vs rag.

  python experiments/collect_metrics.py            -> in bang Markdown + ghi experiments/metrics.csv

Cot:
  findings / crit / high / med / low   so lo hong Strix bao cao (theo severity)
  with_cwe                             ti le finding co gan CWE
  tokens_in / tokens_out / cost_usd    chi phi LLM cua Strix (tu run.json)
  kb_calls                             so lan agent goi Knowledge Base (chi mode rag)
  juice_solved                         so challenge Juice Shop duoc danh dau da giai (ground truth khach quan)
  minutes                              thoi gian chay
Precision / recall / do tin cay judge lay tu experiments/auto_label.py (tu dong, khong lam tay).
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

EXP = Path(__file__).resolve().parent


def find_usage(obj) -> dict:
    """Tim de quy cac khoa token/cost trong run.json (cau truc co the doi theo phien ban Strix)."""
    best: dict = {}

    def walk(o):
        nonlocal best
        if isinstance(o, dict):
            keys = set(o)
            if {"input_tokens", "output_tokens"} <= keys and o.get("input_tokens", 0) >= best.get("input_tokens", -1):
                best = {k: o.get(k) for k in ("input_tokens", "output_tokens", "cost", "requests")}
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    return best


def kb_calls_by_run() -> Counter:
    path = EXP / "kb_tool_calls.jsonl"
    c: Counter = Counter()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                c[json.loads(line).get("run")] += 1
            except json.JSONDecodeError:
                pass
    return c


def main():
    runs_csv = EXP / "runs.csv"
    if not runs_csv.exists():
        print("Chua co run nao (experiments/runs.csv).")
        return
    kb_calls = kb_calls_by_run()
    rows = []
    for r in csv.DictReader(runs_csv.open(encoding="utf-8")):
        run_dir = EXP / "strix_runs" / (r.get("run_dir") or "__none__")
        vulns = []
        if (run_dir / "vulnerabilities.json").exists():
            vulns = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
        sev = Counter(str(v.get("severity", "")).lower() for v in vulns)
        usage = {}
        if (run_dir / "run.json").exists():
            usage = find_usage(json.loads((run_dir / "run.json").read_text(encoding="utf-8")))
        rows.append({
            "label": r["label"], "target": r["target"], "mode": r["mode"], "model": r["model"],
            "scan": r["scan_mode"], "findings": len(vulns),
            "crit": sev["critical"], "high": sev["high"], "med": sev["medium"], "low": sev["low"] + sev["info"],
            "with_cwe": f"{sum(1 for v in vulns if v.get('cwe')) / len(vulns):.0%}" if vulns else "-",
            "tokens_in": usage.get("input_tokens") or "", "tokens_out": usage.get("output_tokens") or "",
            "cost_usd": round(usage["cost"], 3) if isinstance(usage.get("cost"), (int, float)) else "",
            "kb_calls": kb_calls.get(r["label"], 0) if r["mode"] == "rag" else "-",
            "juice_solved": r.get("juice_solved_after") or "-",
            "minutes": round(int(r["seconds"] or 0) / 60, 1),
        })

    cols = list(rows[0])
    print("| " + " | ".join(cols) + " |")
    print("|" + "---|" * len(cols))
    for row in rows:
        print("| " + " | ".join(str(row[c]) for c in cols) + " |")
    with open(EXP / "metrics.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    # chat luong (tu dong): ket qua cua experiments/auto_label.py
    summ_path = EXP / "auto_label_summary.json"
    if not summ_path.exists():
        print("\n(Chua co nhan tu dong -> chay: python experiments/auto_label.py)")
        return
    print("\n### Chat luong finding (gan nhan tu dong)\n")
    qcols = ["label", "mode", "tp", "fp", "uncertain", "dup", "precision", "recall_catalog", "juice_solved",
             "judge_sens", "judge_spec", "judge_kappa"]
    print("| " + " | ".join(qcols) + " |")
    print("|" + "---|" * len(qcols))
    for s in json.loads(summ_path.read_text(encoding="utf-8")):
        jc = s.get("judge_check") or {}
        s = {**s, "judge_sens": jc.get("sensitivity"), "judge_spec": jc.get("specificity"), "judge_kappa": jc.get("kappa")}
        print("| " + " | ".join("-" if s.get(c) is None else str(s.get(c)) for c in qcols) + " |")


if __name__ == "__main__":
    main()
