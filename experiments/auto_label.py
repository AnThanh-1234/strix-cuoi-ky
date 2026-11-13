"""Gan nhan TP/FP/DUP TU DONG cho finding cua Strix - khong can lam tay.

4 lop (uu tien tu tren xuong):
  1. DUP      : trung (vuln_type, endpoint chuan hoa) voi finding truoc do trong cung run
  2. CATALOG  : khop danh sach lo hong da biet (targets/ground_truth.json) theo endpoint + loai loi -> TP
                (Juice Shop: cong them bang chung challenge da giai cung nhom trong run)
  3. JUDGE    : LLM giam khao (khac ho model voi Strix) cham dua tren evidence + tai lieu CWE tu KB
  4. KIEM DINH: chay judge tren (a) finding da co nhan CATALOG va (b) MAU DOI CHUNG AM tu sinh
                (cung finding nhung evidence bi thay bang phan hoi binh thuong) -> do nhay, do dac hieu,
                Cohen's kappa cua judge. Day la so lieu chung minh bo cham tu dong dang tin.

Ket qua:
  experiments/labels_auto.csv          nhan tung finding (+ nguon nhan, ly do)
  experiments/auto_label_summary.json  precision / recall / kiem dinh judge theo tung run

  python experiments/auto_label.py               # tat ca run
  python experiments/auto_label.py --no-judge    # chi DUP + CATALOG (khong goi LLM)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

EXP = Path(__file__).resolve().parent
ROOT = EXP.parent
sys.path.insert(0, str(ROOT / "rag"))
from taxonomy import classify_title, parse_cwe, types_for_cwe  # noqa: E402

GT = json.loads((ROOT / "targets" / "ground_truth.json").read_text(encoding="utf-8"))

JUDGE_SYSTEM = """You are a strict senior penetration-test reviewer. You receive ONE finding produced by an
automated AI pentest agent against a deliberately vulnerable lab app. Decide if the finding is REAL based
ONLY on the evidence given.

Rubric:
- "TP": the evidence shows concrete proof the issue exists (e.g. data of another user returned, SQL error or
  boolean/time difference caused by the payload, script reflected unencoded in an executable context,
  command/file output, forged token accepted, missing header actually shown in a real response).
- "FP": evidence is missing, generic, contradicts the claim, shows normal/intended behaviour, a 4xx/404,
  a payload that was encoded/blocked, or the claim is purely theoretical.
- "UNCERTAIN": evidence is partially consistent but not conclusive.
Do not trust the agent's own severity or wording; trust only request/response evidence.
Answer ONLY JSON: {"verdict": "TP|FP|UNCERTAIN", "confidence": 0.0-1.0, "reason": "<= 2 sentences"}"""

NEG_EVIDENCE = ("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Request processed normally. "
                "The submitted payload does not appear in the response and no error or behavioural "
                "difference was observed compared with a benign request.</body></html>")


# ------------------------------------------------------------------ helpers
def finding_types(f: dict) -> set[str]:
    t = set(classify_title(f"{f.get('title', '')} {f.get('cwe', '')}"))
    c = parse_cwe(f.get("cwe"))
    if c:
        t |= set(types_for_cwe(c))
    return t


def norm_endpoint(f: dict) -> str:
    ep = str(f.get("endpoint") or "")
    path = urlparse(ep).path if "://" in ep else ep.split("?")[0]
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path.rstrip("/"))
    return path.lower()


def haystack(f: dict) -> str:
    return " ".join(str(f.get(k) or "") for k in ("endpoint", "title", "description", "evidence", "technical_analysis"))


def match_catalog(f: dict, target: str) -> tuple[dict | None, dict | None]:
    """Tra ve (entry khop cu the, entry generic khop)."""
    cat = GT.get(target)
    if not cat:
        return None, None
    types = finding_types(f)
    ep = str(f.get("endpoint") or "")
    hay = haystack(f)
    specific = generic = None
    for e in cat["entries"]:
        if not types & set(e["vuln_types"]):
            continue
        text = hay if not e.get("generic") else ep
        if any(re.search(p, ep, re.I) or (not e.get("generic") and re.search(p, text, re.I)) for p in e["path_patterns"]):
            if e.get("generic"):
                generic = generic or e
            else:
                specific = specific or e
    return specific, generic


def juice_solved_categories(run_dir: Path) -> set[str]:
    snap = run_dir / "juice_challenges.json"
    if not snap.exists():
        return set()
    return {c["category"] for c in json.loads(snap.read_text(encoding="utf-8")) if c.get("solved")}


def kb_context(f: dict) -> str:
    c = parse_cwe(f.get("cwe"))
    if not c:
        return ""
    try:
        from kb import load_kb
        chunks = load_kb().get_cwe(c)
        return chunks[0]["text"][:900] if chunks else ""
    except Exception:
        return ""


# ------------------------------------------------------------------ judge
def call_judge(f: dict, target: str, evidence_override: str | None = None) -> dict:
    model = os.environ.get("JUDGE_MODEL")
    if not model:
        return {"verdict": "UNCERTAIN", "confidence": 0.0, "reason": "no JUDGE_MODEL configured"}
    clip = lambda v, n: (str(v or "")[:n])  # noqa: E731
    user = (
        f"Target app: {target} (intentionally vulnerable lab)\n"
        f"Title: {f.get('title')}\nSeverity claimed: {f.get('severity')}\nCWE claimed: {f.get('cwe')}\n"
        f"Endpoint: {f.get('method') or ''} {f.get('endpoint')}\n"
        f"Description: {clip(f.get('description'), 1200)}\n"
        f"EVIDENCE:\n{evidence_override if evidence_override is not None else clip(f.get('evidence') or f.get('technical_analysis'), 2500)}\n"
    )
    ref = kb_context(f)
    if ref:
        user += f"\nReference definition (MITRE CWE):\n{ref}\n"
    msgs = [{"role": "system", "content": JUDGE_SYSTEM}, {"role": "user", "content": user}]
    t0 = time.time()
    try:
        if "/" in model:  # provider/model -> LiteLLM (API thuong mai)
            import litellm
            r = litellm.completion(model=model, messages=msgs, temperature=0,
                                   api_key=os.environ.get("JUDGE_API_KEY"), api_base=os.environ.get("JUDGE_API_BASE"),
                                   response_format={"type": "json_object"})
            text = r.choices[0].message.content
        else:  # Ollama native API (qua tunnel Kaggle) -> dat duoc num_ctx nho cho judge
            import requests
            r = requests.post(f"{os.environ['JUDGE_API_BASE'].rstrip('/')}/api/chat", timeout=300,
                              headers={"Authorization": f"Bearer {os.environ.get('JUDGE_API_KEY', '')}"},
                              json={"model": model, "messages": msgs, "stream": False, "format": "json",
                                    "options": {"temperature": 0, "num_ctx": 8192}})
            r.raise_for_status()
            text = r.json()["message"]["content"]
        out = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
        v = str(out.get("verdict", "")).upper()
        out["verdict"] = v if v in ("TP", "FP", "UNCERTAIN") else "UNCERTAIN"
        out["confidence"] = float(out.get("confidence") or 0)
    except Exception as exc:
        out = {"verdict": "UNCERTAIN", "confidence": 0.0, "reason": f"judge error: {exc}"[:200]}
    out["seconds"] = round(time.time() - t0, 1)
    return out


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    pairs = [(a, b) for a, b in pairs if a in ("TP", "FP") and b in ("TP", "FP")]
    n = len(pairs)
    if n == 0:
        return None
    po = sum(a == b for a, b in pairs) / n
    pa = sum(a == "TP" for a, _ in pairs) / n
    pb = sum(b == "TP" for _, b in pairs) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return round((po - pe) / (1 - pe), 3) if pe < 1 else None


# ------------------------------------------------------------------ main
def label_run(row: dict, use_judge: bool, n_neg: int) -> tuple[list[dict], dict]:
    run_dir = EXP / "strix_runs" / (row.get("run_dir") or "__none__")
    vp = run_dir / "vulnerabilities.json"
    findings = json.loads(vp.read_text(encoding="utf-8")) if vp.exists() else []
    target = row["target"] if row["target"] in GT else "other"
    solved_cats = juice_solved_categories(run_dir)
    cat_map = GT.get("juice", {}).get("challenge_category_map", {})

    labels, seen = [], []   # seen: list (types, endpoint, finding_id)
    for f in findings:
        types = finding_types(f) or {f"title:{str(f.get('title', ''))[:40].lower()}"}
        ep = norm_endpoint(f)
        spec, gen = match_catalog(f, target)
        rec = {"label": row["label"], "mode": row["mode"], "target": row["target"], "finding_id": f.get("id"),
               "severity": f.get("severity"), "cwe": f.get("cwe"), "vuln_types": "|".join(sorted(types)),
               "endpoint": f.get("endpoint"), "title": f.get("title"),
               "catalog_entry": (spec or gen or {}).get("id", ""), "verdict": "", "source": "",
               "judge_verdict": "", "judge_conf": "", "reason": ""}
        # trung: cung endpoint chuan hoa VA co it nhat 1 loai loi chung
        dup_of = next((fid for t, e, fid in seen if e == ep and t & types), None)
        if dup_of is not None:
            rec.update(verdict="DUP", source="dedupe", reason=f"trung voi {dup_of}")
            labels.append(rec)
            continue
        seen.append((types, ep, f.get("id")))

        if spec:
            rec.update(verdict="TP", source="catalog", reason=f"khop lo hong da biet: {spec['name']}")
        elif target == "juice" and any(types & set(cat_map.get(c, [])) for c in solved_cats):
            rec.update(verdict="TP", source="juice_challenge", reason="challenge cung nhom duoc giai trong run")

        if use_judge:
            j = call_judge(f, target)
            rec.update(judge_verdict=j["verdict"], judge_conf=j["confidence"])
            if not rec["verdict"]:
                rec.update(verdict=j["verdict"], source="judge", reason=j.get("reason", ""))
        if not rec["verdict"]:
            rec.update(verdict="UNCERTAIN", source="none", reason="khong khop catalog, chua chay judge")
        labels.append(rec)

    # ---- kiem dinh judge: positives = nhan catalog, negatives = mau doi chung am
    pairs, neg_results = [], []
    if use_judge:
        for rec in labels:
            if rec["source"] in ("catalog", "juice_challenge") and rec["judge_verdict"]:
                pairs.append(("TP", rec["judge_verdict"]))
        positives = [f for f, r in zip(findings, labels) if r["source"] in ("catalog", "juice_challenge")]
        for f in positives[:n_neg]:
            j = call_judge(f, target, evidence_override=NEG_EVIDENCE)
            pairs.append(("FP", j["verdict"]))
            neg_results.append(j["verdict"])

    # ---- chi so
    uniq = [r for r in labels if r["verdict"] != "DUP"]
    tp = sum(r["verdict"] == "TP" for r in uniq)
    fp = sum(r["verdict"] == "FP" for r in uniq)
    unc = sum(r["verdict"] == "UNCERTAIN" for r in uniq)
    summary = {"label": row["label"], "target": row["target"], "mode": row["mode"], "model": row["model"],
               "findings": len(labels), "dup": len(labels) - len(uniq), "tp": tp, "fp": fp, "uncertain": unc,
               "precision": round(tp / (tp + fp), 3) if tp + fp else None}
    if target in GT:
        entries = [e for e in GT[target]["entries"] if not e.get("generic")]
        hit = {r["catalog_entry"] for r in uniq if r["verdict"] == "TP" and r["catalog_entry"]}
        hit &= {e["id"] for e in entries}
        summary["recall_catalog"] = round(len(hit) / len(entries), 3)
        summary["catalog_hit"] = sorted(hit)
    snap = run_dir / "juice_challenges.json"
    if snap.exists():
        ch = json.loads(snap.read_text(encoding="utf-8"))
        summary["juice_solved"] = f"{sum(c['solved'] for c in ch)}/{len(ch)}"
    if pairs:
        pos = [b for a, b in pairs if a == "TP"]
        summary["judge_check"] = {
            "n_pos": len(pos), "n_neg": len(neg_results),
            "sensitivity": round(sum(v == "TP" for v in pos) / len(pos), 3) if pos else None,
            "specificity": round(sum(v == "FP" for v in neg_results) / len(neg_results), 3) if neg_results else None,
            "kappa": cohen_kappa(pairs),
        }
    return labels, summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-judge", action="store_true")
    ap.add_argument("--neg", type=int, default=10, help="so mau doi chung am toi da moi run")
    ap.add_argument("--only", help="chi cham run co label chua chuoi nay")
    a = ap.parse_args()

    env = EXP / ".env"
    if env.exists():  # nap JUDGE_* tu .env
        for line in env.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^(JUDGE_[A-Z_]+)=(.*)$", line.strip())
            if m:
                os.environ.setdefault(m.group(1), m.group(2))

    runs = list(csv.DictReader((EXP / "runs.csv").open(encoding="utf-8")))
    if a.only:
        runs = [r for r in runs if a.only in r["label"]]
    all_labels, summaries = [], []
    for r in runs:
        print(f"[*] {r['label']}", file=sys.stderr)
        labels, s = label_run(r, use_judge=not a.no_judge, n_neg=a.neg)
        all_labels += labels
        summaries.append(s)
        print("    " + json.dumps({k: s.get(k) for k in ("findings", "tp", "fp", "uncertain", "precision",
                                                         "recall_catalog", "judge_check")}), file=sys.stderr)
    if all_labels:
        with open(EXP / "labels_auto.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(all_labels[0]))
            w.writeheader()
            w.writerows(all_labels)
    (EXP / "auto_label_summary.json").write_text(json.dumps(summaries, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"-> {EXP / 'labels_auto.csv'}\n-> {EXP / 'auto_label_summary.json'}", file=sys.stderr)


if __name__ == "__main__":
    main()
