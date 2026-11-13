"""Truy xuat Knowledge Base: hybrid search = dense (embedding) + sparse (BM25), hop nhat bang RRF.

Vi sao hybrid?
  - Dense hieu nghia ("lam sao chong chen cau lenh SQL" ~ "parameterized queries").
  - BM25 bat chinh xac ma dinh danh ("CWE-89", "WSTG-INPV-05", ten header) ma embedding hay bo lo.
  - Reciprocal Rank Fusion (RRF) gop 2 bang xep hang ma khong can can chinh thang diem.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
INDEX_DIR = Path(os.environ.get("KB_INDEX_DIR", ROOT / "kb" / "index"))
EMBED_MODEL = os.environ.get("KB_EMBED_MODEL", "BAAI/bge-small-en-v1.5")
CACHE_DIR = Path(os.environ.get("KB_MODEL_CACHE", Path.home() / ".cache" / "fastembed"))
RRF_K = 60

_TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def tokenize(text: str) -> list[str]:
    toks = _TOKEN_RE.findall(text.lower())
    # "cwe-89" -> giu ca "cwe-89" lan "cwe", "89" de khop linh hoat
    out = []
    for t in toks:
        out.append(t)
        if "-" in t:
            out.extend(t.split("-"))
    return out


@lru_cache(maxsize=1)
def get_embedder():
    from fastembed import TextEmbedding
    return TextEmbedding(model_name=EMBED_MODEL, cache_dir=str(CACHE_DIR))


class KnowledgeBase:
    def __init__(self, index_dir: Path = INDEX_DIR):
        from rank_bm25 import BM25Okapi

        if not (index_dir / "chunks.jsonl").exists():
            raise FileNotFoundError(f"Chua co index tai {index_dir}. Chay: python rag/build_index.py")
        with open(index_dir / "chunks.jsonl", encoding="utf-8") as f:
            self.chunks: list[dict] = [json.loads(line) for line in f]
        self.vecs = np.load(index_dir / "embeddings.npy")
        self.meta = json.loads((index_dir / "meta.json").read_text(encoding="utf-8"))
        # doc_id (WSTG-INJT-05, CWE-89, ten cheat sheet) dua vao BM25 cua MOI chunk -> tra ma ID chinh xac
        self.bm25 = BM25Okapi([tokenize(f"{c['doc_id']} {' '.join(c.get('cwe', []))} {c['text']}")
                               for c in self.chunks])
        self._by_cwe: dict[str, list[int]] = {}
        for i, c in enumerate(self.chunks):
            if c["source"] == "cwe":
                self._by_cwe.setdefault(c["doc_id"], []).append(i)

    # ------------------------------------------------------------------ search
    def _mask(self, source: str | list[str] | None, vuln_type: str | None) -> np.ndarray:
        mask = np.ones(len(self.chunks), dtype=bool)
        if source:
            allowed = {source} if isinstance(source, str) else set(source)
            mask &= np.array([c["source"] in allowed for c in self.chunks])
        if vuln_type:
            mask &= np.array([vuln_type in c["vuln_types"] for c in self.chunks])
        return mask

    def search(
        self,
        query: str,
        top_k: int = 5,
        source: str | list[str] | None = None,
        vuln_type: str | None = None,
        mode: str = "hybrid",
        max_per_doc: int = 2,
    ) -> list[dict]:
        """Tra ve top_k chunk (kem `score`, `rank_dense`, `rank_bm25`).

        mode: "hybrid" | "dense" | "bm25"  (de so sanh trong bao cao)
        max_per_doc: gioi han so chunk tu cung 1 tai lieu -> ket qua da dang hon
        """
        mask = self._mask(source, vuln_type)
        if vuln_type and not mask.any():          # loai chua co tai lieu -> bo loc
            mask = self._mask(source, None)
        idx = np.flatnonzero(mask)
        if idx.size == 0:
            return []

        pool = min(idx.size, max(50, top_k * 10))
        fused: dict[int, float] = {}
        r_dense: dict[int, int] = {}
        r_bm25: dict[int, int] = {}

        if mode in ("hybrid", "dense"):
            q = np.asarray(next(iter(get_embedder().query_embed([query]))), dtype=np.float32)
            q /= np.linalg.norm(q) + 1e-12
            sims = self.vecs[idx] @ q
            for r, j in enumerate(np.argsort(-sims)[:pool]):
                i = int(idx[j])
                r_dense[i] = r + 1
                fused[i] = fused.get(i, 0.0) + 1.0 / (RRF_K + r + 1)
        if mode in ("hybrid", "bm25"):
            scores = np.asarray(self.bm25.get_scores(tokenize(query)))[idx]
            for r, j in enumerate(np.argsort(-scores)[:pool]):
                if scores[j] <= 0:
                    break
                i = int(idx[j])
                r_bm25[i] = r + 1
                fused[i] = fused.get(i, 0.0) + 1.0 / (RRF_K + r + 1)

        results, per_doc = [], {}
        for i, s in sorted(fused.items(), key=lambda kv: -kv[1]):
            c = self.chunks[i]
            key = (c["source"], c["doc_id"])
            if per_doc.get(key, 0) >= max_per_doc:
                continue
            per_doc[key] = per_doc.get(key, 0) + 1
            results.append({**c, "score": round(s, 5), "rank_dense": r_dense.get(i), "rank_bm25": r_bm25.get(i)})
            if len(results) >= top_k:
                break
        return results

    def get_cwe(self, cwe_id: str | int) -> list[dict]:
        m = re.search(r"\d+", str(cwe_id))
        return [self.chunks[i] for i in self._by_cwe.get(f"CWE-{m.group(0)}", [])] if m else []


def format_results(results: list[dict], max_chars: int = 1400) -> str:
    """Dinh dang ket qua de dua vao prompt LLM, co nhan [S#] de trich dan."""
    out = []
    for n, r in enumerate(results, 1):
        tags = []
        if r.get("cwe"):
            tags.append(", ".join(r["cwe"][:4]))
        if r.get("top10"):
            tags.append(", ".join(r["top10"][:2]))
        head = f"[S{n}] {r['doc_title']} > {r['section']}  ({r['source']})"
        body = r["text"].split("\n\n", 1)[-1]
        if len(body) > max_chars:
            body = body[:max_chars].rsplit(" ", 1)[0] + " ..."
        out.append(f"{head}\nURL: {r['url']}" + (f"\nTags: {' | '.join(tags)}" if tags else "") + f"\n{body}")
    return "\n\n---\n\n".join(out) if out else "(khong tim thay tai lieu phu hop)"


@lru_cache(maxsize=1)
def load_kb() -> KnowledgeBase:
    return KnowledgeBase()
