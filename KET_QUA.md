# Kết quả triển khai và thực nghiệm: Strix + Web Security Knowledge Base (RAG)

> Thời gian thực hiện: 12–13/11/2026 · Người phụ trách: Thành An
> Hướng dẫn cài đặt và sử dụng: [README.md](README.md) · Số liệu thô: [experiments/](experiments/)

**Tóm tắt:** Toàn bộ hệ thống đã được triển khai và kiểm chứng: lab mục tiêu, Strix, Knowledge Base RAG tích hợp vào Strix qua MCP, LLM server trên GPU Kaggle, và bộ chấm TP/FP tự động. Hai kết quả chính:
1. **Model open-source cỡ 14B–32B (GPU miễn phí) không điều khiển nổi Strix:** 0 finding sau 3 lần quét Juice Shop, dù biết lập kế hoạch nhưng không chuyển sang bước thực thi.
2. **Model thương mại `gemini-2.5-flash` làm được, nhưng key free tier chỉ cho 20 request/ngày** — không đủ cho một lần quét hoàn chỉnh. Trong 17 phút trước khi hết quota, nó đã **khai thác thành công 1 challenge của Juice Shop** (điều mà qwen3 không bao giờ đạt tới), xác nhận năng lực model chính là nghẽn, không phải hạ tầng.

---

## 1. Hạ tầng đã triển khai

| Thành phần | Trạng thái | Ghi chú |
|---|---|---|
| Docker Engine 29.9.3 trong WSL2 (Ubuntu 22.04) | ✅ | Không dùng Docker Desktop. Phải chuyển iptables sang `legacy` vì kernel WSL 5.10 thiếu module `addrtype` |
| RAM cấp cho WSL | ✅ Tăng từ 3.5 GB lên 5 GB | `C:\Users\ADMIN\.wslconfig` |
| OWASP Juice Shop (`:3000`) | ✅ | 118 challenge, tự reset trước mỗi lần quét |
| DVWA (`:8080`) | ✅ | Database được tạo tự động (`scripts/lab.sh dvwa-setup`) |
| Strix 1.7.0 + sandbox `strix-sandbox:1.3.0` (5.9 GB) | ✅ | Gọi được target qua `host.docker.internal` |
| Knowledge Base (6112 chunk) | ✅ | Mục 2 |
| MCP server `owasp_kb` tích hợp vào Strix | ✅ | Mục 3 |
| LLM server trên Kaggle GPU (T4 x2) | ✅ | Mục 4 |
| Bộ chấm TP/FP tự động | ✅ | Mục 5 |

### Kaggle

- **Notebook LLM server:** https://www.kaggle.com/code/nguyenphanthanhan/attt-strix-llm-server
  (đang để **private**, chỉ chủ tài khoản xem được; nếu cần nộp thì chuyển sang public trong phần Settings của notebook)
- Phiên bản 1: `qwen3:14b` + `gemma3:12b`. Phiên bản 2–3: `qwen3:32b` + `gemma3:12b`, có proxy giữ kết nối.
- Phần cứng: 2 × Tesla T4 (15 GB mỗi GPU), Internet bật.

---

## 2. Knowledge Base (RAG)

### 2.1. Dữ liệu

| Nguồn | Phiên bản | Số chunk | Vai trò | License |
|---|---|---|---|---|
| OWASP Cheat Sheet Series | commit `ef7070e` (137 cheat sheet) | 2747 | Phòng chống, khắc phục | CC BY-SA 4.0 |
| OWASP WSTG | commit `2144357` (170 trang) | 1321 | Phương pháp kiểm thử | CC BY-SA 4.0 |
| MITRE CWE | v5.0 (984 weakness) | 2044 | Phân loại, hậu quả, giảm thiểu | CWE ToU |
| NVD CVE API | gọi trực tiếp | — | Lỗ hổng mới theo sản phẩm / phiên bản | Public |
| **Tổng** | | **6112** | Mỗi chunk trung bình 915 ký tự, dài nhất 3196 | |

- Embedding: `BAAI/bge-small-en-v1.5`, 384 chiều, chạy trên CPU. Build mất **1072 giây (khoảng 18 phút)**.
- Metadata mỗi chunk: `source`, `doc_title`, `section`, `url`, `vuln_types` (33 loại, đặt trùng tên skill của Strix), `cwe`, `top10` (lấy từ `IndexTopTen.md` của OWASP), `license`.
- Có **3580/6112 chunk (59%) không gắn được `vuln_type`**. Phần lớn là CWE không liên quan tới web, hoặc tài liệu chung (threat modeling, logging…).

### 2.2. Đánh giá truy xuất (28 câu hỏi có đáp án)

| Cách tìm | Hit@1 | Hit@3 | Hit@5 | MRR |
|---|---|---|---|---|
| Dense (vector) | 0.607 | 0.786 | 0.857 | 0.695 |
| **BM25 (từ khóa)** | **0.714** | **0.929** | **0.929** | **0.804** |
| Hybrid (RRF) | 0.643 | 0.857 | 0.893 | 0.753 |

**Nhận xét:**
- **BM25 tốt nhất.** Truy vấn bảo mật chứa nhiều thuật ngữ và mã định danh chính xác (`CWE-79`, `WSTG-INJT-05`, `innerHTML`, `169.254.169.254`).
- Dense thất bại rõ ở các mã ID: truy vấn `CWE-79` trả về `CWE-790`, `CWE-791`, `CWE-792`, vì embedding coi các chuỗi gần giống nhau là tương tự.
- Hybrid đứng giữa. Gộp kết quả bằng RRF với trọng số bằng nhau làm kết quả kém của dense kéo BM25 xuống. Hướng cải thiện: tăng trọng số cho BM25, hoặc phát hiện truy vấn dạng mã ID để chuyển thẳng sang BM25.
- Đưa `doc_id` vào corpus của BM25 làm MRR của BM25 tăng từ 0.751 lên 0.804.
- Giới hạn: bộ câu hỏi nhỏ (28), nên chênh lệch giữa các cách tìm chỉ tương đương 1–3 câu.

### 2.3. Kiểm tra chức năng

| Kiểm tra | Kết quả |
|---|---|
| MCP server khởi động (stdio, client MCP như Strix dùng) | 1.9 giây, 4 tool: `search_security_kb`, `get_cwe`, `lookup_cve`, `list_vuln_types` |
| `search_security_kb("JWT alg none signature bypass", source="wstg")` | Đúng mục *WSTG: JSON Web Tokens > Signature Verification > The None Algorithm*, 0.7 giây |
| `get_cwe("CWE-639")` | Đúng *Authorization Bypass Through User-Controlled Key* |
| `lookup_cve("CVE-2021-44228")` | Log4Shell, CVSS 10.0, từ NVD, 1.0 giây |
| Log mỗi lần gọi tool | ✅ `kb_tool_calls.jsonl` (để đo agent có dùng KB không) |
| Hậu xử lý báo cáo (`enrich_report.py --no-llm`), 2 finding mẫu | SQLi gắn đúng CWE-89, SQLi Prevention CS và WSTG SQLi. IDOR gắn đúng IDOR Prevention CS, **nhưng gợi ý sai CWE-286** (đúng phải là CWE-639) |

---

## 3. Tích hợp RAG vào Strix

| Mức | Cách làm | Trạng thái |
|---|---|---|
| 1. Hậu xử lý | `rag/enrich_report.py` đọc `vulnerabilities.json`, truy xuất tài liệu, để LLM viết phân tích có trích dẫn `[S#]` | ✅ Đã test (chưa có finding thật để chạy) |
| 2. Trong lúc quét | MCP server `owasp_kb` đưa vào Strix qua `--mcp-config` (Strix ≥ 1.7 hỗ trợ sẵn, **không cần fork**) | ✅ Đã cấu hình. **Chưa chạy chế độ `rag`**, vì baseline của model nhỏ ra 0 finding nên chưa có gì để so sánh |

Lưu ý khi so sánh với Strix gốc: Strix đã có sẵn **29 skill về lỗ hổng** (`strix/skills/vulnerabilities/*.md`). KB của nhóm có phạm vi rộng hơn nhiều (6112 chunk so với 29 file), có trích dẫn nguồn, cập nhật được bằng cách build lại index, và tra được CVE mới.

---

## 4. LLM server trên Kaggle

```
Strix (WSL) ──HTTPS──► *.trycloudflare.com ──► auth proxy :8000 ──► Ollama (2× T4)
```

| Hạng mục | Kết quả |
|---|---|
| Cài Ollama + tải `qwen3:14b` | 35 giây + 80 giây. Lần chạy đầu (nạp model vào GPU) mất 124 giây |
| `qwen3:32b` | 26 GB, 100% trên GPU, context 40960 token |
| Xác thực | Thiếu key hoặc sai key bị trả **401** ✅ |
| Gọi tool (`http_request`) | ✅ Cả 14B và 32B đều gọi đúng định dạng và tự đề xuất payload thử SQLi |
| Độ trễ khi test (prompt ngắn) | 14B: 37.9 giây · 32B: 58–79 giây |
| Độ trễ trong lúc quét thật (prompt khoảng 20K token) | 14B: khoảng 1 phút mỗi lượt · **32B: khoảng 3–4 phút mỗi lượt** |

**Các sự cố đã gặp và cách xử lý:**
1. **Strix giả định context 200K token** với model mà nó không biết. Đã đặt `STRIX_CONTEXT_FALLBACK_TOKENS=40960` và các ngưỡng nén context cho phù hợp.
2. **Lỗi Cloudflare 524**: tunnel cắt request nếu không có phản hồi trong khoảng 100 giây, mà model 32B xử lý prompt dài vượt mức đó. Đã viết lại proxy để gửi tín hiệu giữ kết nối mỗi 15 giây (dòng comment SSE cho request stream, khoảng trắng cho JSON). Đã test với upstream giả chậm 35 giây. Trong lần quét 32B: 17/18 request LLM thành công.
3. **Hai model không vừa VRAM cùng lúc** (32B + giám khảo): cho giữ 1 model trên GPU (`MAX_LOADED=1`) và nạp model chính sau cùng.
4. `kaggle kernels logs` chỉ trả log sau khi kernel đã kết thúc. Phải dùng `-f` để đọc URL tunnel khi kernel đang chạy.

**Quota GPU đã dùng:** khoảng 2.5 giờ trên khoảng 30 giờ mỗi tuần. Server đã được tắt.

---

## 5. Bộ chấm TP/FP tự động (không cần làm tay)

| Lớp | Cách làm | Kiểm tra |
|---|---|---|
| DUP | Cùng endpoint (đã chuẩn hóa ID) và có chung loại lỗi | ✅ Hai finding SQLi cùng `/rest/user/login` được gộp đúng |
| CATALOG | Khớp danh sách lỗi đã biết: DVWA 16 module, Juice Shop 30 endpoint, cùng các challenge đã giải | ✅ SQLi ở login khớp `login_sqli`, IDOR basket khớp `basket_idor`, XSS DVWA khớp `xss_r` |
| JUDGE | `gemma3:12b`, khác họ với model của Strix, chấm theo rubric chỉ tin evidence | ✅ Evidence SQLi thật chấm là **TP** (0.95, 12.7 giây). Mẫu đối chứng âm chấm là **FP** (0.95, 3.8 giây) |
| Kiểm định | Độ nhạy, độ đặc hiệu, Cohen's kappa trên các finding CATALOG và các mẫu đối chứng âm tự sinh | Đã cài đặt. Chưa có số liệu vì chưa có finding thật |

---

## 6. Kết quả quét

Mục tiêu: Juice Shop · Chế độ: `baseline` · Scan mode: `quick`

| # | Model | Cấu hình | Thời gian | Lượt LLM | Token vào / ra | Chi phí | Finding | Challenge đã giải |
|---|---|---|---|---|---|---|---|---|
| 1 | qwen3:14b | mặc định | 5.1 phút | 4 | 81,928 / 2,212 | $0 (Kaggle) | **0** | 0/118 |
| 2 | qwen3:14b | ép gọi tool + gợi ý cho model nhỏ | 14.8 phút | 16 | 327,712 / 7,870 | $0 (Kaggle) | **0** | 0/118 |
| 3 | qwen3:32b | như #2 | 54.9 phút | 17 | 348,194 / 9,661 | $0 (Kaggle) | **0** | 0/118 |
| 4 | **gemini-2.5-flash** | mặc định | 16.9 phút* | 23 ok / 48 thử | 1,415,246 / 4,532 | ~$0.19** | 0 *(chưa kịp ghi)* | **1/118** |

\* Dừng giữa chừng vì hết quota free tier (exit code 1). \*\* Ước tính theo bảng giá; free tier **không bị tính tiền**, chỉ bị chặn số request.

### Agent đã làm gì (theo `strix.log`)

| # | Tool được gọi | Hành vi |
|---|---|---|
| 1 | `web_search` (lỗi vì không có key), rồi `finish_scan` | Viết kết luận "không có lỗ hổng" mà **không gửi request nào** tới target |
| 2 | `update_coverage` ×7, `list_coverage` ×3, `repeat_request` ×1 (lỗi), `finish_scan` | Chủ yếu là các thao tác ghi chép tiến độ. Chỉ 1 lần thử gửi request |
| 3 | `view_agent_graph` ×3, `create_agent` ×2, `save_threat_model`, `get_threat_model`, `finish_scan` | **Biết lập kế hoạch** (tạo sub-agent "Threat Modeler", xây threat model), nhưng **không chuyển sang được bước thực thi** (thăm dò, gửi payload) |
| 4 | `create_agent`, `save/get_threat_model`, `create_note`, gửi request thật tới target | **Thực sự khai thác**: dò target, gây lỗi làm lộ stack trace → **giải được challenge "Error Handling"** (Security Misconfiguration). Hết quota (20 req/ngày) sau 31 lượt, trước khi kịp gọi `report_vulnerability` nên chưa ghi finding vào file |

**Điểm đáng chú ý ở lần 4:** 0 finding được *ghi* nhưng 1 challenge được *giải thật* (ground truth khách quan từ `/api/Challenges`). Đây đúng là trường hợp bộ chấm dựa trên challenge-solved bắt được còn đếm số finding thì bỏ sót.

Thư mục run: `experiments/strix_runs/host-docker-internal-3000_{650b,f4a3,c69f,6c59}/`

### Giới hạn quota Gemini free tier

```
Quota exceeded for metric: generate_content_free_tier_requests, limit: 20, model: gemini-2.5-flash
Generate content requests per day limit exceeded on Free Tier. Please retry in 14h18m.
```

Free tier chỉ cho **20 request/ngày/model**. Một lần quét Strix `quick` cần hàng chục request (lần 4 đã thử 48 request). Vì vậy **không thể hoàn thành một lần quét với key free tier**. Để chạy tiếp cần **bật billing** (pay-as-you-go) trên key tại Google AI Studio — khi đó giới hạn tăng lên hàng nghìn request/phút, và chi phí thực tế rất nhỏ (~$0.19 cho lần quét này).

---

## 7. Kết luận

### 7.1. Về Strix (trả lời các câu hỏi của thầy)

| Câu hỏi | Kết luận từ thực nghiệm |
|---|---|
| **Mô hình / luồng hoạt động** | Strix là hệ multi-agent: Root Agent lập kế hoạch, tạo sub-agent (Threat Modeler, tester…), các sub-agent dùng tool trong sandbox Docker (browser, proxy, shell), báo cáo qua `report_vulnerability`, rồi gọi `finish_scan`. Hệ thống đòi hỏi LLM thực hiện **chuỗi dài** các lần gọi tool có mục tiêu rõ ràng. |
| **Phụ thuộc loại model** | **Phụ thuộc rất mạnh.** Model 14B–32B gọi đúng *từng* tool riêng lẻ nhưng không duy trì được chuỗi pentest nhiều bước (0 finding). `gemini-2.5-flash` thì bắt đầu khai thác được ngay (giải 1 challenge trong 17 phút). Ranh giới "quét được / không quét được" nằm ở năng lực model. |
| **Đầu tư mua token?** | Model miễn phí (Kaggle) tốn $0 token nhưng chậm và **không ra kết quả**. Model thương mại ra kết quả với chi phí token rất nhỏ (~$0.19/lần quét với Gemini Flash), **nhưng key free tier bị chặn ở 20 request/ngày — không đủ dùng**. Kết luận thực tế: cần một **key có bật billing**; chi phí token không đáng kể, rào cản thật là *phải có tài khoản trả phí* chứ không phải *giá đắt*. Strix có `--max-budget` để chặn trần chi phí. |
| **Build model nhỏ?** | Fine-tune model nhỏ khó đạt năng lực điều khiển agent như trên, trong phạm vi 5 tuần. Hướng hợp lý hơn: model nhỏ đảm nhiệm **các tác vụ hẹp** như chấm TP/FP (`gemma3:12b` chấm đúng cả 2 mẫu thử), phân loại CWE, viết báo cáo. Model lớn đảm nhiệm điều khiển agent. |
| **Lỗi mới** | KB có tool `lookup_cve` tra NVD trực tiếp, và index build lại được khi OWASP/CWE cập nhật. |

### 7.2. Về RAG
- Pipeline RAG hoạt động tốt: truy xuất đúng tài liệu cho các câu hỏi bảo mật (Hit@3 = 0.93 với BM25). Tích hợp được vào Strix qua MCP mà không phải sửa mã nguồn.
- **Với dữ liệu bảo mật, tìm kiếm theo từ khóa (BM25) quan trọng không kém tìm kiếm ngữ nghĩa**, vì có nhiều mã định danh chính xác.
- **Chưa đo được tác động của RAG lên hiệu quả quét**, vì baseline của model nhỏ ra 0 finding. RAG bổ sung *kiến thức*, còn nghẽn hiện tại là *năng lực thực thi* của model. Hai thứ này khác nhau, và RAG không bù được cho thứ thứ hai.

### 7.3. Hạn chế
- Mỗi cấu hình mới chạy 1 lần, chưa lặp lại để đo độ dao động.
- Mới quét Juice Shop, chưa quét DVWA.
- Chưa chạy chế độ `rag` và chưa chạy hậu xử lý với LLM trên finding thật — **bị chặn bởi quota 20 req/ngày của Gemini free tier**. Đây là rào cản chính còn lại.
- Lần quét Gemini chưa chạy xong (hết quota), chưa kịp ghi finding nào vào file dù đã giải được 1 challenge.
- Danh sách lỗi Juice Shop được tổng hợp thủ công (30 endpoint), chưa phủ hết 118 challenge.
- Giám khảo mới được kiểm tra trên 2 mẫu.

---

## 8. Việc cần làm tiếp

1. **Bật billing cho key Gemini** tại Google AI Studio (hoặc dùng key trả phí của Anthropic/OpenAI). Đây là điều kiện bắt buộc để hoàn thành một lần quét — key free tier hiện tại chặn ở 20 request/ngày. Chi phí token rất nhỏ (~$0.19/lần quét).
2. Chạy ma trận thực nghiệm `{Juice Shop, DVWA} × {baseline, rag}`, mỗi ô 2 lần, giới hạn 2 USD mỗi lần quét (ước tính tổng ≤ 16 USD).
3. Chạy `auto_label.py` (giám khảo trên Kaggle) và `collect_metrics.py` để có precision, recall, kappa của giám khảo, và số lần agent gọi KB.
4. Chạy `enrich_report.py` (có LLM) để so sánh chất lượng báo cáo có và không có RAG.
5. Cải thiện hybrid search: tăng trọng số BM25, hoặc chuyển thẳng truy vấn dạng mã ID sang BM25.

### Lệnh tái hiện

```bash
cd /mnt/d/cac_mon_hoc/ATTT && . ~/.venvs/attt-rag/bin/activate
scripts/lab.sh up
scripts/kaggle_llm.sh start 6                   # hoặc điền key API vào experiments/.env
scripts/run_scan.sh juice baseline quick 2
scripts/run_scan.sh juice rag      quick 2
python experiments/auto_label.py && python experiments/collect_metrics.py
python rag/eval_retrieval.py
```
