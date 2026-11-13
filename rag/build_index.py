"""Xay dung Web Application Security Knowledge Base tu cac nguon OWASP/MITRE.

Pipeline:  Markdown/XML  ->  chunk theo heading  ->  gan metadata  ->  embedding  ->  luu index

Dau ra (thu muc kb/index/):
  chunks.jsonl     moi dong la 1 chunk {id, source, doc_title, section, text, url, vuln_types, cwe, top10, ...}
  embeddings.npy   ma tran float32 [N, dim], da chuan hoa L2 (cosine = dot product)
  meta.json        thong tin phien ban: model, so chunk, commit nguon, thoi diem build

Chay:  python rag/build_index.py            (toan bo)
       python rag/build_index.py --limit 50 (thu nhanh)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from taxonomy import classify_title, top10_for_types, types_for_cwe  # noqa: E402
from kb import EMBED_MODEL, get_embedder, INDEX_DIR, ROOT  # noqa: E402

SRC = ROOT / "kb" / "sources"
CS_DIR = SRC / "CheatSheetSeries"
WSTG_DIR = SRC / "wstg" / "document"

MAX_CHARS = 1800      # kich thuoc toi da 1 chunk (~450 token)
MIN_CHARS = 250       # section ngan hon se duoc gop vao section ke tiep
OVERLAP_PARAS = 1     # so doan van lap lai khi phai cat section dai

HEADING_RE = re.compile(r"^(#{1,4})\s+(.*?)\s*#*\s*$")
LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")
IMG_RE = re.compile(r"!\[[^\]]*\]\([^)]+\)")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


# --------------------------------------------------------------------------- markdown

def clean_md(text: str) -> str:
    text = HTML_COMMENT_RE.sub("", text)
    text = IMG_RE.sub("", text)
    text = LINK_RE.sub(r"\1", text)          # giu chu, bo URL -> giam nhieu cho embedding
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def split_sections(md: str) -> list[tuple[list[str], str]]:
    """Tach markdown theo heading, bo qua '#' nam trong code block.

    Tra ve list (heading_path, body)."""
    sections: list[tuple[list[str], str]] = []
    path: list[str] = []
    buf: list[str] = []
    in_code = False

    def flush():
        body = "\n".join(buf).strip()
        if body:
            sections.append((list(path), body))
        buf.clear()

    for line in md.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
        m = None if in_code else HEADING_RE.match(line)
        if m:
            flush()
            level = len(m.group(1))
            path[:] = path[: level - 1] + [m.group(2).strip()]
        else:
            buf.append(line)
    flush()
    return sections


def split_long(body: str) -> list[str]:
    if len(body) <= MAX_CHARS:
        return [body]
    paras = re.split(r"\n\s*\n", body)
    parts, cur = [], []
    for p in paras:
        # doan van/code block qua dai: cat cung theo dong
        while len(p) > MAX_CHARS:
            cut = p.rfind("\n", 0, MAX_CHARS)
            cut = cut if cut > MAX_CHARS // 3 else MAX_CHARS
            parts.append("\n\n".join(cur + [p[:cut]]).strip()) if cur else parts.append(p[:cut])
            cur = []
            p = p[cut:].lstrip()
        if cur and len("\n\n".join(cur + [p])) > MAX_CHARS:
            parts.append("\n\n".join(cur).strip())
            cur = cur[-OVERLAP_PARAS:] if OVERLAP_PARAS else []
            if len("\n\n".join(cur + [p])) > MAX_CHARS:
                cur = []
        cur.append(p)
    if cur:
        parts.append("\n\n".join(cur).strip())
    return [p for p in parts if p.strip()]


def md_to_chunks(md: str, base: dict) -> list[dict]:
    md = clean_md(md)
    raw = split_sections(md)

    # gop section qua ngan vao section ke tiep (giu heading cua section dau)
    merged: list[tuple[list[str], str]] = []
    carry: tuple[list[str], str] | None = None
    for path, body in raw:
        if carry:
            path, body = carry[0], carry[1] + "\n\n" + (" > ".join(path[1:]) + "\n" if len(path) > 1 else "") + body
            carry = None
        if len(body) < MIN_CHARS:
            carry = (path, body)
            continue
        merged.append((path, body))
    if carry:
        if merged:
            p, b = merged[-1]
            merged[-1] = (p, b + "\n\n" + carry[1])
        else:
            merged.append(carry)

    chunks = []
    for path, body in merged:
        section = " > ".join(path[1:]) if len(path) > 1 else "Overview"
        for i, piece in enumerate(split_long(body)):
            c = dict(base)
            c["section"] = section + (f" (part {i + 1})" if i else "")
            # dua tieu de vao text -> embedding biet chunk thuoc tai lieu nao
            c["text"] = f"{base['doc_title']} — {section}\n\n{piece}"
            chunks.append(c)
    return chunks


# --------------------------------------------------------------------------- OWASP Cheat Sheets

def load_top10_index() -> dict[str, list[str]]:
    """Doc IndexTopTen.md cua repo -> {ten_file_cheatsheet: [A0x:2021-...]}."""
    mapping: dict[str, list[str]] = {}
    path = CS_DIR / "IndexTopTen.md"
    if not path.exists():
        return mapping
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        h = re.match(r"^##\s+\[?(A\d\d:\d{4})\s*[–-]\s*([^\]]+)", line)
        if h:
            current = f"{h.group(1)}-{h.group(2).strip()}"
            continue
        for f in re.findall(r"cheatsheets/([\w.-]+\.md)", line):
            if current:
                mapping.setdefault(f, []).append(current)
    return mapping


def build_cheatsheets(limit: int | None) -> list[dict]:
    top10_map = load_top10_index()
    files = sorted((CS_DIR / "cheatsheets").glob("*.md"))[:limit]
    chunks = []
    for f in files:
        md = f.read_text(encoding="utf-8")
        m = re.search(r"^#\s+(.+)$", md, re.MULTILINE)
        title = m.group(1).strip() if m else f.stem.replace("_", " ")
        types = classify_title(title + " " + f.stem)
        cwes = sorted({c for t in types for c in _cwe_of(t)})
        base = {
            "source": "cheatsheet",
            "doc_title": title,
            "doc_id": f.stem,
            "url": f"https://cheatsheetseries.owasp.org/cheatsheets/{f.stem}.html",
            "vuln_types": types,
            "cwe": [f"CWE-{c}" for c in cwes],
            "top10": sorted(set(top10_map.get(f.name, [])) | set(top10_for_types(types))),
            "license": "CC BY-SA 4.0 - OWASP Cheat Sheet Series",
        }
        chunks += md_to_chunks(md, base)
    return chunks


# --------------------------------------------------------------------------- OWASP WSTG

def build_wstg(limit: int | None) -> list[dict]:
    files = sorted((WSTG_DIR / "4-Web_Application_Security_Testing").rglob("*.md"))
    files = [f for f in files if f.name != "README.md"][:limit]
    chunks = []
    for f in files:
        md = f.read_text(encoding="utf-8")
        m = re.search(r"^#\s+(.+)$", md, re.MULTILINE)
        title = m.group(1).strip() if m else f.stem
        wid = re.search(r"WSTG-[A-Z]{4}-\d{2}(?:\.\d+)?", md)
        category = f.parent.name.split("-", 1)[-1].replace("_", " ")
        types = classify_title(title + " " + f.stem)
        cwes = sorted({c for t in types for c in _cwe_of(t)})
        rel = f.relative_to(WSTG_DIR).with_suffix("")
        base = {
            "source": "wstg",
            "doc_title": f"WSTG: {title}",
            "doc_id": wid.group(0) if wid else f.stem,
            "wstg_category": category,
            "url": f"https://owasp.org/www-project-web-security-testing-guide/latest/{rel.as_posix()}",
            "vuln_types": types,
            "cwe": [f"CWE-{c}" for c in cwes],
            "top10": top10_for_types(types),
            "license": "CC BY-SA 4.0 - OWASP WSTG",
        }
        chunks += md_to_chunks(md, base)
    return chunks


# --------------------------------------------------------------------------- MITRE CWE

def _txt(el) -> str:
    if el is None:
        return ""
    return re.sub(r"\s+", " ", " ".join(el.itertext())).strip()


def build_cwe(limit: int | None) -> list[dict]:
    xml = sorted(SRC.glob("cwec_v*.xml"))
    if not xml:
        print("  ! khong tim thay CWE XML, bo qua", file=sys.stderr)
        return []
    root = ET.parse(xml[-1]).getroot()
    ns = {"c": root.tag.split("}")[0].strip("{")}
    chunks = []
    weaknesses = [w for w in root.iterfind(".//c:Weaknesses/c:Weakness", ns)
                  if w.get("Status") not in ("Deprecated", "Obsolete")][:limit]
    for w in weaknesses:
        cid = int(w.get("ID"))
        name = w.get("Name")
        types = types_for_cwe(cid) or classify_title(name)
        alt = [_txt(t.find("c:Term", ns)) for t in w.iterfind("c:Alternate_Terms/c:Alternate_Term", ns)]
        conseq = []
        for c in w.iterfind("c:Common_Consequences/c:Consequence", ns):
            scope = ", ".join(_txt(s) for s in c.iterfind("c:Scope", ns))
            impact = ", ".join(_txt(s) for s in c.iterfind("c:Impact", ns))
            conseq.append(f"- {scope}: {impact}")
        detect = [f"- {_txt(d.find('c:Method', ns))}: {_txt(d.find('c:Description', ns))[:300]}"
                  for d in w.iterfind("c:Detection_Methods/c:Detection_Method", ns)]
        mitig = [f"- [{_txt(m.find('c:Phase', ns))}] {_txt(m.find('c:Description', ns))}"
                 for m in w.iterfind("c:Potential_Mitigations/c:Mitigation", ns)]
        cves = [_txt(o.find("c:Reference", ns)) + ": " + _txt(o.find("c:Description", ns))
                for o in w.iterfind("c:Observed_Examples/c:Observed_Example", ns)][:5]

        title = f"CWE-{cid}: {name}"
        base = {
            "source": "cwe",
            "doc_title": title,
            "doc_id": f"CWE-{cid}",
            "url": f"https://cwe.mitre.org/data/definitions/{cid}.html",
            "vuln_types": types,
            "cwe": [f"CWE-{cid}"],
            "top10": top10_for_types(types),
            "abstraction": w.get("Abstraction"),
            "license": "MITRE CWE Terms of Use",
        }
        overview = [f"Description: {_txt(w.find('c:Description', ns))}"]
        ext = _txt(w.find("c:Extended_Description", ns))
        if ext:
            overview.append(f"Extended: {ext[:900]}")
        if alt:
            overview.append("Also known as: " + ", ".join(a for a in alt if a))
        if conseq:
            overview.append("Common consequences:\n" + "\n".join(conseq[:6]))
        if cves:
            overview.append("Observed examples:\n" + "\n".join(f"- {c}" for c in cves))
        chunks.append({**base, "section": "Overview", "text": f"{title}\n\n" + "\n\n".join(overview)[:MAX_CHARS]})

        if mitig or detect:
            body = ""
            if mitig:
                body += "Potential mitigations:\n" + "\n".join(mitig)
            if detect:
                body += "\n\nDetection methods:\n" + "\n".join(detect[:5])
            for i, piece in enumerate(split_long(body.strip())):
                sec = "Mitigations & Detection" + (f" (part {i + 1})" if i else "")
                chunks.append({**base, "section": sec, "text": f"{title} — {sec}\n\n{piece}"})
    return chunks


def _cwe_of(vtype: str) -> list[int]:
    from taxonomy import VULN_TYPES
    return VULN_TYPES[vtype]["cwe"]


# --------------------------------------------------------------------------- main

def git_commit(path: Path) -> str | None:
    try:
        return subprocess.check_output(["git", "-C", str(path), "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None, help="so tai lieu toi da moi nguon (de test)")
    ap.add_argument("--batch", type=int, default=64)
    args = ap.parse_args()

    t0 = time.time()
    chunks: list[dict] = []
    for name, fn in [("cheatsheet", build_cheatsheets), ("wstg", build_wstg), ("cwe", build_cwe)]:
        part = fn(args.limit)
        print(f"[+] {name:10s}: {len(part):5d} chunks")
        chunks += part
    for i, c in enumerate(chunks):
        c["id"] = f"{c['source']}:{c['doc_id']}:{i}"

    print(f"[*] Embedding {len(chunks)} chunks bang {EMBED_MODEL} (CPU)...")
    emb = get_embedder()
    vecs = np.asarray(list(emb.passage_embed([c["text"] for c in chunks], batch_size=args.batch)), dtype=np.float32)
    vecs /= np.linalg.norm(vecs, axis=1, keepdims=True) + 1e-12

    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    with open(INDEX_DIR / "chunks.jsonl", "w", encoding="utf-8") as f:
        for c in chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    np.save(INDEX_DIR / "embeddings.npy", vecs)

    lengths = [len(c["text"]) for c in chunks]
    meta = {
        "embed_model": EMBED_MODEL,
        "dim": int(vecs.shape[1]),
        "n_chunks": len(chunks),
        "by_source": dict(Counter(c["source"] for c in chunks)),
        "by_vuln_type": dict(Counter(t for c in chunks for t in c["vuln_types"]).most_common()),
        "untyped_chunks": sum(1 for c in chunks if not c["vuln_types"]),
        "chunk_chars": {"mean": int(np.mean(lengths)), "max": int(max(lengths))},
        "sources": {
            "CheatSheetSeries": git_commit(CS_DIR),
            "wstg": git_commit(WSTG_DIR.parent),
            "cwe_xml": [p.name for p in SRC.glob("cwec_v*.xml")],
        },
        "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "build_seconds": round(time.time() - t0, 1),
    }
    (INDEX_DIR / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: meta[k] for k in ("n_chunks", "by_source", "untyped_chunks", "chunk_chars", "build_seconds")}))


if __name__ == "__main__":
    main()
