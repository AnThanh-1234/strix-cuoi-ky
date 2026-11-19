# Hướng dẫn chạy Webapp + Strix (cấu hình hiện tại)

> File này mô tả **cách hệ thống đang chạy thực tế**: webapp và Strix đều chạy trong **WSL Ubuntu**,
> còn **Docker Desktop trên Windows** làm engine. Không bật Juice Shop / DVWA khi quét target ngoài,
> cũng không bật server LLM — Strix gọi trực tiếp Gemini bằng key trong `experiments/.env`.
>
> File hướng dẫn cũ (lab + RAG đầy đủ): [HUONG_DAN_CHAY.md](HUONG_DAN_CHAY.md).

---

## 1. Kiến trúc tổng quan

```
Windows
├── Docker Desktop (engine, API TCP 127.0.0.1:2375)
└── Trình duyệt → http://127.0.0.1:8765
        │
WSL Ubuntu (networkingMode=mirrored → dùng chung localhost với Windows)
├── web/app.py          (webapp, queue scan, SQLite)
└── scripts/run_scan.sh → strix 1.7.0
        ├── DOCKER_HOST=tcp://127.0.0.1:2375  → sandbox container
        └── Gemini API (key từ experiments/.env)
```

Nguyên tắc quan trọng:

- **Strix dùng Docker SDK (Python)**, không dùng lệnh `docker` CLI. Vì vậy phải có `DOCKER_HOST`,
  không phải chỉ có wrapper `docker` chạy được.
- Webapp chạy trên Linux → `command_for()` trong `web/app.py` tự sinh lệnh
  `bash scripts/run_scan.sh ...` (không cần `wsl.exe`).
- Với target là URL ngoài, `run_scan.sh` **bỏ qua `lab.sh up`** → không khởi động Juice Shop/DVWA.
- `run_scan.sh` kết thúc bằng `exit "$RC"` → Strix lỗi thì webapp ghi đúng `Failed`.

---

## 2. Cấu hình một lần (đã làm trên máy này)

### 2.1. WSL: Ubuntu là distro mặc định + mirrored networking

Từ PowerShell:

```powershell
wsl -s Ubuntu
```

Tạo/sửa `C:\Users\<bạn>\.wslconfig`:

```ini
[wsl2]
networkingMode=mirrored
```

Rồi restart WSL:

```powershell
wsl --shutdown
```

> `mirrored` giúp WSL dùng chung `localhost` với Windows → `127.0.0.1:2375` và `127.0.0.1:8765`
> đi lại được hai chiều. Để đảo lại: xóa `.wslconfig` rồi `wsl --shutdown`.

### 2.2. Docker Desktop: mở API TCP 2375

Không cần bật WSL Integration và cũng không cần cài Docker Engine trong Ubuntu.
Sửa `C:\Users\<bạn>\AppData\Roaming\Docker\settings-store.json`, thêm:

```json
"ExposeDockerAPIOnTCP2375": true
```

File hiện tại có dạng:

```json
{
  "AutoStart": false,
  "DisplayedOnboarding": true,
  "ExposeDockerAPIOnTCP2375": true,
  "InferenceCanUseGPUVariant": true,
  "LastContainerdSnapshotterEnable": 1792666374,
  "LicenseTermsVersion": 2,
  "SettingsVersion": 46
}
```

Restart Docker Desktop (GUI hoặc lệnh):

```powershell
& "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe" desktop restart
```

Kiểm tra từ Windows:

```powershell
curl.exe http://127.0.0.1:2375/_ping     # → OK
```

### 2.3. Docker CLI wrapper trong WSL (tiện kiểm tra, không bắt buộc)

Tạo `~/.local/bin/docker` trong Ubuntu:

```bash
mkdir -p ~/.local/bin
cat > ~/.local/bin/docker <<'EOF'
#!/usr/bin/env bash
# Goi Docker Desktop engine tu WSL (khong can cai Docker Engine trong WSL).
DD_DOCKER="/mnt/c/<bạn>/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe"
args=()
for a in "$@"; do
  case "$a" in
    /mnt/*) args+=("$(wslpath -w "$a")") ;;
    *) args+=("$a") ;;
  esac
done
exec "$DD_DOCKER" "${args[@]}"
EOF
chmod +x ~/.local/bin/docker
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

Thay `<bạn>` bằng tên user Windows (máy này là `nptha`).

### 2.4. Cài Strix và kéo image sandbox

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv tool install --python 3.12 strix-agent
strix --version                     # strix 1.7.0

export DOCKER_HOST=tcp://127.0.0.1:2375
docker pull ghcr.io/usestrix/strix-sandbox:1.3.0
docker info | grep -E 'Server Version|Operating System'
# Server Version: 29.9.2 / Operating System: Docker Desktop
```

Kiểm tra bằng đúng Python của Strix (cách chắc nhất):

```bash
export DOCKER_HOST=tcp://127.0.0.1:2375
~/.local/share/uv/tools/strix-agent/bin/python - <<'PY'
import docker
c = docker.from_env()
print("ping:", c.ping(), "images:", len(c.images.list()))
PY
# ping: True images: 2
```

### 2.5. Khóa Gemini

`experiments/.env` (đã có, **không commit**):

```
STRIX_LLM=gemini/gemini-2.5-flash
LLM_API_KEY=<key Gemini có billing>
```

Nếu gặp `429 / RESOURCE_EXHAUSTED`, đổi thành:

```
STRIX_LLM=gemini/gemini-3-flash-preview
```

> Không cần bật Ollama / LLM server local / proxy TPM.

---

## 3. Chạy hằng ngày

### Bước 1 — Windows: đảm Docker Desktop đang chạy

```powershell
& "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe" desktop status
```

Sandbox của Strix nằm ở Docker Desktop, nên Docker phải bật trong suốt lượt scan.

### Bước 2 — WSL: khởi động webapp

```bash
cd "/mnt/d/Thanh/TLHT/HK 9/ATTT/strix-cuoi-ky"
python3 web/app.py
```

Chạy nền:

```bash
nohup python3 web/app.py > /tmp/strix-web.log 2>&1 &
```

Log ban đầu:

```
Strix Web Pentest: http://127.0.0.1:8765
Database: .../web/data/strix_web.sqlite3
Local-only mode; no login is configured.
```

### Bước 3 — Windows: mở webapp

```
http://127.0.0.1:8765
```

Kiểm tra nhanh:

```powershell
curl.exe http://127.0.0.1:8765/api/settings
# {"strix_configured": true, "demo_mode": false, ...}
```

### Bước 4 — Tạo target và scan trên giao diện

- Vào **Targets** → thêm target (`https://sv.dut.udn.vn/Default.aspx`) → xác nhận authorized.
- Vào **Scan** → chọn target đó.
- Chọn:
  - `mode = baseline` — `rag` **chưa dùng được** vì chưa cài Knowledge Base (xem mục 5).
  - `depth = quick`
  - `budget = 1` (USD) để thử nghiệm.
- Nhấn Scan, theo dõi log trực tiếp trên webapp.

Log sẽ có dòng:

```
[*] Target ngoai: bo qua lab.sh up (khong khoi dong Juice Shop/DVWA).
[*] <label>  model=gemini/...  scan=quick  budget=$1  target=...
```

Kết quả: `web/data/strix_web.sqlite3`, log ở `web/data/logs/scan-*.log`,
run của Strix ở `experiments/strix_runs/<label>/`.

> ⚠️ Chỉ quét target bạn có quyền kiểm thử chính thức. `sv.dut.udn.vn` là site thật.

---

## 4. Chạy Strix trực tiếp (không qua webapp)

```bash
cd "/mnt/d/Thanh/TLHT/HK 9/ATTT/strix-cuoi-ky"
scripts/run_scan.sh "http://localhost:3000" baseline quick 1
# cú pháp: run_scan.sh <target> <baseline|rag> [quick|standard|deep] [budget USD]
```

- `juice` / `dvwa` → script sẽ gọi `scripts/lab.sh up` và khởi động lab.
- URL bất kỳ → **không** khởi động lab.
- Biến `DOCKER_HOST` được script tự đặt, không cần export thủ công.

---

## 5. (Tùy chọn) Cài RAG để dùng `mode = rag`

Hiện **chưa cài**. Muốn dùng thì chạy trong WSL:

```bash
uv venv --python 3.12 ~/.venvs/attt-rag
source ~/.venvs/attt-rag/bin/activate
uv pip install -r rag/requirements.txt
bash rag/fetch_sources.sh
python rag/build_index.py          # ~15-20 phút, khoảng 6100 chunk
python rag/query.py "how to test JWT none algorithm" --source wstg --brief
```

Sau khi có `kb/index/`, chọn `mode = rag` trên webapp. Agent sẽ gọi MCP `owasp_kb`
qua `call_mcp`; kiểm tra các lần gọi trong `experiments/kb_tool_calls.jsonl`.

---

## 6. Xử lý sự cố

| Triệu chứng | Nguyên nhân | Cách sửa |
|---|---|---|
| `DOCKER NOT AVAILABLE / Cannot connect to Docker at default socket` | Strix SDK tìm `/var/run/docker.sock`, không có trong Ubuntu | Đảm `ExposeDockerAPIOnTCP2375: true`, `.wslconfig` có `networkingMode=mirrored`, đã `wsl --shutdown`; `run_scan.sh` tự export `DOCKER_HOST=tcp://127.0.0.1:2375` |
| `curl 127.0.0.1:2375/_ping` trong WSL bị `Connection refused` | Docker Desktop tắt hoặc chưa restart sau sửa settings | `docker desktop restart`, đợi vài giây, thử lại |
| `/bin/sh: bash: not found` (exit 127) | Lệnh chạy nhầm distro `docker-desktop` | `wsl -s Ubuntu`; webapp phải chạy **trong Ubuntu**, không gọi `wsl.exe` từ Windows |
| `OSError: [Errno 98] Address already in use` khi bật webapp | Có tiến trình khác giữ 8765 (hoặc vừa tắt xong còn TIME_WAIT) | Windows: `netstat -ano \| findstr :8765`; WSL: `ss -ltn \| grep 8765`, kill PID rồi thử lại |
| Scan báo `Completed` nhưng log có `exit=1` | Script cũ thiếu `exit "$RC"` | Đã sửa: cuối `scripts/run_scan.sh` có `exit "$RC"` |
| `429 / RESOURCE_EXHAUSTED` | Vượt TPM của Gemini 2.5 Flash | Đổi `STRIX_LLM=gemini/gemini-3-flash-preview` trong `experiments/.env` |
| `kb_calls = 0` ở chế độ `rag` | Chưa cài KB, hoặc agent gọi sai tên tool | Cài mục 5; prompt trong `run_scan.sh` đã dùng đúng `call_mcp` + `connection='owasp_kb'` |
| Không vào được webapp từ Windows | Webapp bind sai host/port | `HOST = 127.0.0.1`, `PORT` lấy từ `STRIX_WEB_PORT` (mặc định 8765); kiểm tra `curl.exe http://127.0.0.1:8765/api/settings` |

---

## 7. Bản đồ file cấu hình

| Việc | File |
|---|---|
| API Docker cho Strix | `C:\Users\<bạn>\AppData\Roaming\Docker\settings-store.json` → `ExposeDockerAPIOnTCP2375` |
| WSL dùng chung localhost | `C:\Users\<bạn>\.wslconfig` → `networkingMode=mirrored` |
| Distro mặc định | `wsl -s Ubuntu` |
| Key/model LLM | `experiments/.env` (không commit) |
| Export `DOCKER_HOST`, bỏ lab với URL ngoài, trả exit code | `scripts/run_scan.sh` |
| Sinh lệnh scan theo OS | `web/app.py` → `command_for()` |
| Cơ sở dữ liệu webapp | `web/data/strix_web.sqlite3` |
| Log scan | `web/data/logs/scan-*.log` |
| Kết quả Strix | `experiments/strix_runs/<label>/` |

---

## 8. Lệnh nhanh

```powershell
# Windows: trạng thái Docker / webapp
& "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe" desktop status
curl.exe http://127.0.0.1:2375/_ping
curl.exe http://127.0.0.1:8765/api/settings
```

```bash
# WSL: kiểm tra đầy đủ trước khi scan
export PATH="$HOME/.local/bin:$PATH"
export DOCKER_HOST=tcp://127.0.0.1:2375
curl -s http://127.0.0.1:2375/_ping; echo
docker info | grep -E 'Server Version|Operating System'
curl -s http://127.0.0.1:8765/api/settings; echo

# WSL: bật webapp / scan trực tiếp
cd "/mnt/d/Thanh/TLHT/HK 9/ATTT/strix-cuoi-ky"
python3 web/app.py
scripts/run_scan.sh "http://localhost:3000" baseline quick 1
```
