# Triển khai Strix + Web Application Security Knowledge Base (RAG)

Đồ án cuối kỳ ATTT: triển khai **Strix** (AI agent pentest mã nguồn mở) trên lab cục bộ, đánh giá hiệu quả quét, và bổ sung một **Knowledge Base RAG** gồm OWASP Cheat Sheets, OWASP WSTG và MITRE CWE, kèm tra cứu CVE trực tiếp từ NVD.

> ⚠️ Chỉ quét các ứng dụng trong lab (`targets/`). Không trỏ Strix vào hệ thống không có quyền kiểm thử.

## 1. Kiến trúc

```mermaid
flowchart LR
    subgraph WSL2["WSL2 Ubuntu 22.04"]
        subgraph Docker
            SB["Strix sandbox<br/>(browser, proxy, tools)"]
            JS["Juice Shop :3000"]
            DV["DVWA :8080"]
        end
        ST["Strix CLI<br/>(multi-agent)"] -- điều khiển --> SB
        SB -- HTTP tấn công --> JS & DV
        ST -- "MCP stdio (chế độ rag)" --> MCP["rag/mcp_server.py<br/>search_security_kb · get_cwe · lookup_cve"]
        MCP --> KB[("kb/index<br/>chunks + embeddings")]
        ST --> RUN["strix_runs/&lt;run&gt;/vulnerabilities.json"]
        RUN --> EN["rag/enrich_report.py<br/>(mức 1: hậu xử lý)"]
        EN --> KB
    end
    ST <-- API --> LLM["LLM (Claude / GPT / Ollama local)"]
    MCP -. HTTPS .-> NVD["NVD CVE API"]
```

RAG được tích hợp ở **hai mức**:

| Mức | Cách làm | Ảnh hưởng |
|---|---|---|
| 1. Hậu xử lý | `enrich_report.py` đọc báo cáo Strix, truy xuất tài liệu và để LLM viết phân tích có trích dẫn `[S#]` | Chất lượng báo cáo: root cause, khắc phục, CWE đúng, phát hiện false positive |
| 2. Trong lúc quét | MCP server `owasp_kb` được đưa vào Strix qua `--mcp-config`. Agent tự tra WSTG trước khi test và tra Cheat Sheet trước khi báo cáo | Hiệu quả quét: phương pháp test, độ phủ, loại lỗi mới (CVE) |

Ghi chú: Strix đã có sẵn 29 *skill* về lỗ hổng (`strix/skills/vulnerabilities/*.md`). KB của nhóm khác ở chỗ phạm vi rộng hơn nhiều (137 cheat sheet, 150+ trang WSTG, ~980 CWE), có trích dẫn nguồn, và cập nhật được bằng cách build lại index mà không cần sửa prompt của Strix.

## 2. Knowledge Base

| Nguồn | Vai trò | License |
|---|---|---|
| [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries) | Phòng chống / khắc phục | CC BY-SA 4.0 |
| [OWASP WSTG](https://github.com/OWASP/wstg) | Phương pháp kiểm thử | CC BY-SA 4.0 |
| [MITRE CWE](https://cwe.mitre.org/data/downloads.html) | Phân loại điểm yếu, hậu quả, giảm thiểu | CWE Terms of Use |
| NVD CVE API (live) | Lỗ hổng mới theo sản phẩm / phiên bản | Public |

**Pipeline** ([rag/build_index.py](rag/build_index.py)):

1. Chia chunk theo heading Markdown (bỏ qua `#` nằm trong code block), gộp section ngắn hơn 250 ký tự, cắt section dài hơn 1800 ký tự và giữ lại 1 đoạn chồng lấp.
2. Gắn metadata cho mỗi chunk: `source`, `doc_title`, `section`, `url`, `vuln_types` (đặt trùng tên skill của Strix, xem [rag/taxonomy.py](rag/taxonomy.py)), `cwe`, `top10` (lấy từ `IndexTopTen.md` của OWASP), `license`.
3. Embedding: `BAAI/bge-small-en-v1.5` (384 chiều, chạy ONNX trên CPU qua fastembed, không cần GPU).
4. Truy xuất **hybrid**: dense (cosine) kết hợp BM25, hợp nhất bằng Reciprocal Rank Fusion. Mỗi tài liệu đóng góp tối đa 2 chunk để kết quả đa dạng.

## 3. Cài đặt (đã thực hiện trên máy này)

| Thành phần | Vị trí |
|---|---|
| Docker Engine 29 (trong WSL, không dùng Docker Desktop) | `sudo service docker start` |
| Strix 1.7.0 | `~/.local/bin/strix` (cài bằng `uv tool`, Python 3.12) |
| Python venv của RAG | `~/.venvs/attt-rag` |
| RAM của WSL | `C:\Users\ADMIN\.wslconfig` → `memory=5GB` |

Chỉ cài lại khi chuyển sang máy khác:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy   # bắt buộc trên WSL kernel 5.10
sudo usermod -aG docker $USER && sudo service docker start
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install --python 3.12 strix-agent
uv venv --python 3.12 ~/.venvs/attt-rag && . ~/.venvs/attt-rag/bin/activate
uv pip install -r rag/requirements.txt
bash rag/fetch_sources.sh && python rag/build_index.py
```

## 4. Sử dụng

Mở terminal Ubuntu (WSL), chạy `cd /mnt/d/cac_mon_hoc/ATTT && . ~/.venvs/attt-rag/bin/activate`, rồi:

```bash
scripts/lab.sh up                 # bật Docker + Juice Shop (localhost:3000) + DVWA (localhost:8080, admin/password)

# Tra cứu KB
python rag/query.py "JWT alg none bypass" --source wstg --brief
python rag/eval_retrieval.py      # đánh giá Hit@k / MRR: dense vs bm25 vs hybrid

# Model: model nhỏ trên Kaggle GPU (T4 x2) qua Cloudflare tunnel
scripts/kaggle_llm.sh start 8     # push kernel private, chờ tunnel, tự ghi cấu hình vào experiments/.env
scripts/kaggle_llm.sh test        # thử chat + tool calling
scripts/kaggle_llm.sh stop        # tắt khi xong (quota GPU khoảng 30 giờ/tuần)
#   (hoặc dùng API thương mại: cp experiments/.env.example experiments/.env rồi điền key)

# Một lần thực nghiệm:  <juice|dvwa> <baseline|rag> [quick|standard|deep] [budget USD]
scripts/run_scan.sh juice baseline quick 2
scripts/run_scan.sh juice rag      quick 2

# Hậu xử lý báo cáo bằng RAG
python rag/enrich_report.py experiments/strix_runs/<run> --no-llm   # chỉ gắn tài liệu tham chiếu ($0)
python rag/enrich_report.py experiments/strix_runs/<run>            # LLM phân tích có trích dẫn

# Chấm TP/FP tự động rồi tổng hợp số liệu
python experiments/auto_label.py
python experiments/collect_metrics.py
```

### Kaggle LLM server ([kaggle/llm_server.py](kaggle/llm_server.py))

```
Strix (WSL) ──HTTPS──► *.trycloudflare.com ──► auth proxy :8000 (Bearer key) ──► Ollama (2× T4)
                                                                              ├─ qwen3:14b   (agent cho Strix)
                                                                              └─ gemma3:12b  (giám khảo chấm TP/FP)
```

- Kernel ở chế độ **private**. Key ngẫu nhiên nằm trong `experiments/.kaggle_llm` (quyền 600, không commit). Gọi mà không có key thì nhận lỗi 401.
- Strix không biết context window của model nhỏ (mặc định giả định 200k), nên script đặt `STRIX_CONTEXT_FALLBACK_TOKENS=40960`, thu nhỏ ngưỡng nén context, và giới hạn độ dài output của tool.
- URL tunnel đổi mỗi lần khởi động. Chạy `scripts/kaggle_llm.sh url` để cập nhật lại `.env`.

## 5. Thiết kế thực nghiệm

**Biến độc lập:** chế độ (`baseline` / `rag`) × model (API lớn / model nhỏ local) × mục tiêu (Juice Shop / DVWA).
Mỗi cấu hình nên chạy ít nhất 2 lần, vì agent LLM cho kết quả khác nhau giữa các lần chạy.

| Chỉ số | Nguồn | Ý nghĩa |
|---|---|---|
| Số finding theo severity | `vulnerabilities.json` | Độ phủ |
| **Precision** = TP / (TP+FP) | `auto_label.py` (tự động) | Độ tin cậy |
| **Recall** theo danh sách lỗi đã biết | `targets/ground_truth.json` | Độ phủ trên lỗi đã biết |
| Juice Shop challenges solved | `juice_challenges.json` (snapshot sau mỗi run) | Ground truth khách quan |
| Độ nhạy / độ đặc hiệu / kappa của giám khảo | `auto_label_summary.json` | Bộ chấm tự động có đáng tin không |
| Token in/out, chi phí USD | `run.json` | Trả lời câu hỏi "có nên đầu tư mua token" |
| Thời gian | `runs.csv` | Hiệu năng |
| Số lần agent gọi KB | `kb_tool_calls.jsonl` | Agent có thực sự dùng RAG hay không |
| Hit@k / MRR | `eval_retrieval.py` | Chất lượng truy xuất |

**Gán nhãn tự động** ([experiments/auto_label.py](experiments/auto_label.py)), không có bước làm tay:

1. **DUP:** cùng endpoint (đã chuẩn hóa ID, ví dụ `/basket/5` thành `/basket/{id}`) và có chung loại lỗi với một finding trước đó.
2. **CATALOG:** khớp endpoint và loại lỗi với danh sách lỗi đã biết của DVWA (16 module) hoặc Juice Shop (30 endpoint), hoặc có challenge Juice Shop cùng nhóm được giải trong run. Những finding này tính là TP.
3. **JUDGE:** `gemma3:12b`, khác họ với model của Strix, chấm phần còn lại theo rubric chặt: chỉ tin vào evidence request/response, có kèm định nghĩa CWE lấy từ KB.
4. **Kiểm định giám khảo:** cho giám khảo chấm (a) các finding đã có nhãn CATALOG, kết quả đúng phải là TP, và (b) các **mẫu đối chứng âm** tự sinh (cùng finding nhưng evidence được thay bằng phản hồi bình thường), kết quả đúng phải là FP. Từ đó tính độ nhạy, độ đặc hiệu và Cohen's kappa. Trong báo cáo, con số này thay cho việc đối chiếu với người chấm.

**Hạn chế cần nêu trong báo cáo:** danh sách lỗi Juice Shop được tổng hợp từ tài liệu *Pwning OWASP Juice Shop*, chưa đầy đủ 118 challenge. Giám khảo LLM vẫn có thể sai, nên luôn báo cáo kèm các chỉ số kiểm định. Juice Shop và DVWA nổi tiếng nên có thể đã nằm trong dữ liệu huấn luyện của LLM. Nên bổ sung một app nhỏ tự viết, có lỗi cài sẵn, để kiểm tra khả năng tìm lỗi mà model chưa từng thấy.

## 6. Cấu trúc thư mục

```
targets/docker-compose.yml     Juice Shop + DVWA
rag/
  fetch_sources.sh             tải OWASP CheatSheetSeries, WSTG, CWE XML
  taxonomy.py                  vuln_type ↔ CWE ↔ OWASP Top 10
  build_index.py               chunk + metadata + embedding → kb/index/
  kb.py                        hybrid search (dense + BM25 + RRF)
  mcp_server.py                MCP server cho Strix (mức 2)
  enrich_report.py             hậu xử lý báo cáo (mức 1)
  query.py, eval_retrieval.py  demo và đánh giá truy xuất
scripts/lab.sh, run_scan.sh    quản lý lab, chạy thực nghiệm
experiments/                   .env, runs.csv, strix_runs/, metrics.csv, labels.csv
kb/sources, kb/index           dữ liệu nguồn và index (tạo lại được)
```

## 7. Bí mật (không commit)

| Bí mật | Vị trí |
|---|---|
| Key LLM cho Strix | `experiments/.env` |
| Token Kaggle | `~/.kaggle/access_token` (trong WSL, quyền 600) |
| Khóa SSH của máy ảo | `*.pem` — nên chuyển ra `~/.ssh/` |