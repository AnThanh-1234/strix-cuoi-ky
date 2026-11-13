"""CLI tra cuu Knowledge Base (dung de demo / kiem tra nhanh).

  python rag/query.py "how to test for JWT none algorithm"
  python rag/query.py "prevent IDOR" --source cheatsheet -k 3
  python rag/query.py "CWE-918" --mode bm25
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kb import format_results, load_kb  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("query")
ap.add_argument("-k", "--top-k", type=int, default=5)
ap.add_argument("--source", choices=["cheatsheet", "wstg", "cwe"])
ap.add_argument("--vuln-type")
ap.add_argument("--mode", choices=["hybrid", "dense", "bm25"], default="hybrid")
ap.add_argument("--brief", action="store_true", help="chi in tieu de + diem")
a = ap.parse_args()

res = load_kb().search(a.query, top_k=a.top_k, source=a.source, vuln_type=a.vuln_type, mode=a.mode)
if a.brief:
    for i, r in enumerate(res, 1):
        print(f"[S{i}] {r['score']:.4f}  dense#{r['rank_dense']}  bm25#{r['rank_bm25']}  "
              f"{r['source']:10s} {r['doc_title']} > {r['section']}")
else:
    print(format_results(res))
