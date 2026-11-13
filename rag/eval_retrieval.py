"""Danh gia chat luong truy xuat: Hit@k va MRR cho 3 che do dense / bm25 / hybrid.

Moi cau hoi co tai lieu "dung" (doc_id). Hit@k = ti le cau hoi co tai lieu dung trong top-k.
Cau hoi mo phong nhung gi agent/LLM se hoi khi phan tich ket qua kiem thu.

  python rag/eval_retrieval.py          -> in bang + ghi experiments/retrieval_eval.json
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kb import ROOT, load_kb  # noqa: E402

# (cau hoi, cac doc_id chap nhan duoc)  doc_id = ten file cheatsheet | WSTG-ID | CWE-N
GOLD = [
    ("how do I fix SQL injection in a login form", ["SQL_Injection_Prevention_Cheat_Sheet", "Query_Parameterization_Cheat_Sheet"]),
    ("parameterized queries prepared statements", ["SQL_Injection_Prevention_Cheat_Sheet", "Query_Parameterization_Cheat_Sheet"]),
    ("output encoding for HTML attribute context", ["Cross_Site_Scripting_Prevention_Cheat_Sheet"]),
    ("DOM sink innerHTML location.hash injection", ["DOM_based_XSS_Prevention_Cheat_Sheet", "WSTG-CLNT-01"]),
    ("synchronizer token pattern anti forgery", ["Cross-Site_Request_Forgery_Prevention_Cheat_Sheet"]),
    ("SameSite cookie attribute", ["Cross-Site_Request_Forgery_Prevention_Cheat_Sheet", "Session_Management_Cheat_Sheet"]),
    ("server fetches attacker supplied URL cloud metadata 169.254.169.254",
     ["Server_Side_Request_Forgery_Prevention_Cheat_Sheet", "WSTG-INJT-19", "CWE-918"]),
    ("JWT alg none signature not verified", ["JSON_Web_Token_Cheat_Sheet", "WSTG-SESS-10", "CWE-347"]),
    ("user can access another user's order by changing the id", ["Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet", "WSTG-ATHZ-04", "CWE-639"]),
    ("restrict uploaded file extension and content type", ["File_Upload_Cheat_Sheet", "WSTG-BUSL-09", "CWE-434"]),
    ("Access-Control-Allow-Origin reflects arbitrary origin with credentials", ["HTML5_Security_Cheat_Sheet", "WSTG-CLNT-07", "CWE-942"]),
    ("missing Content-Security-Policy and X-Frame-Options headers", ["HTTP_Headers_Cheat_Sheet", "Content_Security_Policy_Cheat_Sheet", "Clickjacking_Defense_Cheat_Sheet"]),
    ("store passwords with bcrypt argon2", ["Password_Storage_Cheat_Sheet"]),
    ("session id not rotated after login", ["Session_Management_Cheat_Sheet", "WSTG-SESS-03", "CWE-384"]),
    ("../../etc/passwd file read via filename parameter", ["WSTG-ATHZ-01", "CWE-22", "File_Upload_Cheat_Sheet"]),
    ("XML external entity DOCTYPE SYSTEM", ["XML_External_Entity_Prevention_Cheat_Sheet", "CWE-611", "WSTG-INJT-07"]),
    ("java deserialization gadget ObjectInputStream", ["Deserialization_Cheat_Sheet", "CWE-502"]),
    ("template injection {{7*7}} jinja2", ["WSTG-INJT-18", "CWE-1336"]),
    ("os command injection via ping parameter", ["OS_Command_Injection_Defense_Cheat_Sheet", "WSTG-INJT-12", "CWE-78"]),
    ("mass assignment isAdmin field in JSON body", ["Mass_Assignment_Cheat_Sheet", "WSTG-INJT-20", "CWE-915"]),
    ("open redirect returnUrl parameter", ["Unvalidated_Redirects_and_Forwards_Cheat_Sheet", "WSTG-CLNT-04", "CWE-601"]),
    ("verbose stack trace error message disclosure", ["Error_Handling_Cheat_Sheet", "WSTG-ERRH-01", "CWE-209"]),
    ("GraphQL introspection enabled batching attack", ["GraphQL_Cheat_Sheet", "WSTG-APIT-99"]),
    ("NoSQL injection $ne operator MongoDB login bypass", ["NoSQL_Security_Cheat_Sheet", "05.6-NoSQL_Injection", "CWE-943"]),
    ("account lockout brute force protection", ["Authentication_Cheat_Sheet", "WSTG-ATHN-03", "CWE-307"]),
    ("CWE-79", ["CWE-79"]),
    ("WSTG-INJT-05", ["WSTG-INJT-05"]),
    ("prompt injection in LLM agent tools", ["LLM_Prompt_Injection_Prevention_Cheat_Sheet", "AI_Agent_Security_Cheat_Sheet", "CWE-1427"]),
]

KS = (1, 3, 5)


def evaluate(kb, mode: str) -> dict:
    hits = {k: 0 for k in KS}
    rr = 0.0
    misses = []
    for q, gold in GOLD:
        res = kb.search(q, top_k=max(KS), mode=mode, max_per_doc=1)
        ids = [r["doc_id"] for r in res]
        rank = next((i + 1 for i, d in enumerate(ids) if d in gold), None)
        for k in KS:
            hits[k] += int(rank is not None and rank <= k)
        rr += 1.0 / rank if rank else 0.0
        if not rank or rank > 3:
            misses.append({"query": q, "got": ids[:3]})
    n = len(GOLD)
    return {"mode": mode, **{f"hit@{k}": round(hits[k] / n, 3) for k in KS}, "mrr": round(rr / n, 3), "misses": misses}


def main():
    kb = load_kb()
    known = {c["doc_id"] for c in kb.chunks}
    missing = sorted({g for _, gs in GOLD for g in gs} - known)
    if missing:
        print("! doc_id khong co trong index (bo qua):", ", ".join(missing))
    out = [evaluate(kb, m) for m in ("dense", "bm25", "hybrid")]
    print(f"\n{len(GOLD)} cau hoi\n{'mode':8s} " + " ".join(f"hit@{k:<4d}" for k in KS) + " MRR")
    for r in out:
        print(f"{r['mode']:8s} " + " ".join(f"{r[f'hit@{k}']:<8.3f}" for k in KS) + f" {r['mrr']:.3f}")
    path = ROOT / "experiments" / "retrieval_eval.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"n_queries": len(GOLD), "results": out}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n-> {path}")


if __name__ == "__main__":
    main()
