# Hướng dẫn chạy chương trình (cho người mới)

> Dành cho người lần đầu chạy dự án này từ số 0. Làm lần lượt từng bước.
> Dự án: triển khai **Strix** (AI agent pentest) + **Knowledge Base RAG** để quét lỗ hổng web, đo xem RAG có giúp Strix quét tốt hơn không.
> Tài liệu khác: [README.md](README.md) (tổng quan kỹ thuật) · [KET_QUA.md](KET_QUA.md) (kết quả) · [TIEN_DO.md](TIEN_DO.md) (tiến độ).

---

## 0. Cần chuẩn bị gì

| Thứ cần | Vì sao | Cách có |
|---|---|---|
| **Windows 10/11 + WSL2 (Ubuntu)** hoặc máy Linux | Strix cần Docker; Docker chạy trong WSL/Linux | `wsl --install` (Windows), hoặc dùng Ubuntu sẵn có |
| **Docker** | Strix dựng sandbox để tấn công app | Cài ở Bước 2 |
| **Git, curl** | Lấy code + tải dữ liệu | `sudo apt install git curl` |
| **Khóa API model trả phí** (Gemini) | Model miễn phí KHÔNG quét được (xem Sự cố) | Google AI Studio, cần bật billing |
| RAM | WSL nên có ≥ 5 GB | File `C:\Users\<bạn>\.wslconfig` |

> ⚠️ **Chỉ quét các app trong lab của dự án** (Juice Shop, DVWA). Tuyệt đối không trỏ Strix vào website thật — đó là tấn công trái phép.

---

## 1. Lấy code

Mở terminal **Ubuntu (WSL)**, không dùng PowerShell cho các bước dưới:

```bash
git clone https://github.com/AnThanh-1234/strix-cuoi-ky.git
cd strix-cuoi-ky
```

(Nếu code đã nằm sẵn ở `D:\cac_mon_hoc\ATTT`, trong WSL vào bằng: `cd /mnt/d/cac_mon_hoc/ATTT`)

---

## 2. Cài môi trường (làm 1 lần)

### 2.1. Docker trong WSL

```bash
curl -fsSL https://get.docker.com | sudo sh
# WSL kernel cũ thiếu module -> bắt buộc chuyển iptables sang legacy:
sudo update-alternatives --set iptables  /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
sudo usermod -aG docker $USER
sudo service docker start
# kiểm tra:
docker run --rm hello-world     # thấy "Hello from Docker!" là OK
```

> Nếu báo lỗi iptables khi `docker run`: chạy lại 2 lệnh `update-alternatives` rồi `sudo service docker start`.

### 2.2. Cài Strix + môi trường Python

```bash
# uv: trình quản lý Python/venv
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"          # thêm dòng này vào ~/.bashrc cho tiện

# Strix (cần Python 3.12):
uv tool install --python 3.12 strix-agent
strix --version                               # thấy số phiên bản là OK

# môi trường Python cho RAG:
uv venv --python 3.12 ~/.venvs/attt-rag
source ~/.venvs/attt-rag/bin/activate
uv pip install -r rag/requirements.txt
```

### 2.3. Tải sẵn image sandbox của Strix (5.9 GB, tải 1 lần)

```bash
docker pull ghcr.io/usestrix/strix-sandbox:1.3.0
```

---

## 3. Dựng Knowledge Base (cơ sở tri thức RAG)

```bash
source ~/.venvs/attt-rag/bin/activate     # nếu chưa bật venv
bash rag/fetch_sources.sh                 # tải OWASP Cheat Sheets + WSTG + CWE
python rag/build_index.py                 # chia chunk + nhúng vector (~15-20 phút, chạy CPU)
```

Xong sẽ có `kb/index/` với ~6100 chunk. Thử tra cứu:

```bash
python rag/query.py "how to test JWT none algorithm" --source wstg --brief
```

---

## 4. Cấu hình model LLM

```bash
cp experiments/.env.example experiments/.env
nano experiments/.env
```

Điền (khuyến nghị dùng **gemini-3-flash-preview** — xem Sự cố để hiểu vì sao):

```
STRIX_LLM=gemini/gemini-3-flash-preview
LLM_API_KEY=<khóa Gemini của bạn>
LLM_TIMEOUT=600
SMALL_MODEL_HINTS=0
```

> ⚠️ **Khóa Gemini phải bật billing** (pay-as-you-go), không dùng free tier (free tier chặn 20 request/ngày — không đủ 1 lần quét). Mỗi lần quét tốn ~1–2 USD.
> ⚠️ **KHÔNG commit file `.env`** (đã được gitignore sẵn).

---

## 5. Chạy thực nghiệm

```bash
cd /mnt/d/cac_mon_hoc/ATTT     # hoặc thư mục repo của bạn
source ~/.venvs/attt-rag/bin/activate

# 5.1. Bật lab (Juice Shop :3000, DVWA :8080)
scripts/lab.sh up

# 5.2. Quét. Cú pháp: run_scan.sh <juice|dvwa> <baseline|rag> [quick|standard|deep] [budget USD]
scripts/run_scan.sh juice baseline quick 2    # không dùng RAG
scripts/run_scan.sh juice rag      quick 2    # có dùng RAG (agent tự tra KB)
```

- `baseline` = Strix quét bình thường. `rag` = Strix được nối Knowledge Base qua MCP.
- Mỗi lần quét ~15–25 phút. Kết quả lưu ở `experiments/strix_runs/<tên_run>/`.
- Muốn biết agent có thực sự tra KB không: xem file `experiments/kb_tool_calls.jsonl` (mỗi dòng = 1 lần agent gọi KB).

---

## 6. Xem kết quả

```bash
# chấm đúng/sai tự động (miễn phí, không gọi LLM)
python experiments/auto_label.py --no-judge

# bảng tổng hợp (findings, precision, kb_calls, chi phí, thời gian...)
python experiments/collect_metrics.py

# đánh giá chất lượng truy xuất của KB
python rag/eval_retrieval.py

# bổ sung phân tích có trích dẫn vào báo cáo (mức 1)
python rag/enrich_report.py experiments/strix_runs/<tên_run> --no-llm
```

Bảng `collect_metrics.py` in ra cột quan trọng: **kb_calls** (số lần agent tra KB — chứng minh RAG hoạt động), **findings**, **precision**, **juice_solved** (challenge giải được — bằng chứng khách quan).

---

## 7. Sự cố thường gặp (QUAN TRỌNG)

### ❌ Quét bị lỗi 429 / RESOURCE_EXHAUSTED liên tục
**Nguyên nhân:** Strix bắn quá nhiều token/phút, vượt giới hạn TPM của model. Gemini 2.5 Flash chỉ 1M token/phút, Strix đạt đỉnh ~1.6M → bị chặn.
**Cách xử lý:**
- Dùng model TPM cao hơn: **`gemini-3-flash-preview` (2M TPM)** trong `.env`. (Khuyến nghị — đơn giản nhất.)
- Hoặc bật **proxy điều tiết** rồi vẫn dùng 2.5-flash: xem mục dưới.

### ❌ Chế độ `rag` nhưng `kb_calls = 0` (agent không tra KB)
**Nguyên nhân:** Strix cho agent dùng KB qua meta-tool `call_mcp`, không phải gọi thẳng. Hướng dẫn phải nói đúng.
**Cách xử lý:** đã sửa sẵn trong `scripts/run_scan.sh` (nhánh `rag`). Nếu tự viết hướng dẫn, phải bảo agent: *"call list_mcps, then call_mcp with connection='owasp_kb', tool='search_security_kb'..."*. Đừng bảo nó gọi `search_security_kb` trực tiếp.

### ❌ Model nhỏ (qwen3, llama...) ra 0 finding
Đây là **kết quả thật**, không phải lỗi: model < 70B không đủ sức điều khiển Strix. Cần model thương mại mạnh (Gemini, Claude, GPT).

### ❌ "failed to connect to the docker API" / Docker tắt
Máy ngủ dậy hoặc khởi động lại thì Docker tắt. Bật lại:
```bash
sudo service docker start      # hoặc: wsl -u root service docker start (từ PowerShell)
scripts/lab.sh up
```

### ❌ Lỗi "too many states for serving" (schema)
Chỉ xảy ra nếu dùng endpoint OpenAI-compat của Gemini. **Dùng provider gốc** `STRIX_LLM=gemini/...` (không phải `openai/...`).

### Proxy điều tiết TPM (khi muốn giữ 2.5-flash)
```bash
# cửa sổ 1: bật proxy (giữ dưới 850K token/phút)
python scripts/tpm_proxy.py
# experiments/.env thêm:  LLM_API_BASE=http://127.0.0.1:8787/v1beta/openai  và  STRIX_LLM=openai/gemini-2.5-flash
```
Lưu ý: cách này vướng lỗi schema ở trên với tool phức tạp của Strix — nên thực tế khuyên dùng gemini-3-flash hơn.

---

## 8. Mỗi lần mở máy lại cần làm gì

```bash
cd /mnt/d/cac_mon_hoc/ATTT
sudo service docker start          # bật lại Docker
scripts/lab.sh up                  # bật lại lab
source ~/.venvs/attt-rag/bin/activate
# rồi chạy quét như Bước 5
```
(Không cần dựng lại Knowledge Base — nó đã lưu ở `kb/index/`.)

---

## 9. Bản đồ lệnh nhanh

| Muốn làm | Lệnh |
|---|---|
| Bật/tắt lab | `scripts/lab.sh up` / `scripts/lab.sh down` |
| Xem lab đang chạy | `scripts/lab.sh status` |
| Quét baseline | `scripts/run_scan.sh juice baseline quick 2` |
| Quét có RAG | `scripts/run_scan.sh juice rag quick 2` |
| Tra cứu KB thử | `python rag/query.py "câu hỏi" --brief` |
| Chấm điểm | `python experiments/auto_label.py --no-judge` |
| Bảng kết quả | `python experiments/collect_metrics.py` |

Gặp vấn đề ngoài danh sách trên: xem thêm [README.md](README.md) phần tương ứng.
