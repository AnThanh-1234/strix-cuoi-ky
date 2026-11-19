# Quyết định phạm vi nghiệp vụ — Web Pentest tích hợp Strix

**Trạng thái:** Đã chốt phạm vi thực hiện  
**Ngày:** 19/11/2026  
**Cơ sở:** Project hiện chạy Strix qua CLI `scripts/run_scan.sh`, lưu cấu hình/log trong `experiments/configs/`, danh sách lượt quét trong `experiments/runs.csv`, và kết quả Strix trong `experiments/strix_runs/<run>/`.

## 1. Quyết định

Xây dựng ứng dụng web cục bộ bổ trợ để quản lý target và quy trình pentest bằng Strix. Không tạo tài khoản hoặc yêu cầu đăng nhập; Strix chịu trách nhiệm thực hiện kiểm thử bảo mật theo target và instruction được giao.

Phạm vi được chọn gồm:

1. Target và xác nhận quyền kiểm thử.
2. Cấu hình, tạo và chạy scan.
3. Hiển thị log thô trong lúc scan đang chạy.
4. Hiển thị findings sau khi scan hoàn tất.
5. Xuất báo cáo HTML, JSON và Markdown.
6. Lịch sử các lượt scan.
7. Quản trị target, lịch scan và cấu hình thông báo.
8. Audit log với actor cục bộ.
9. Lịch quét tự động.
10. Thông báo khi scan hoàn tất hoặc có finding nghiêm trọng.

Ứng dụng chạy cục bộ, chỉ bind `127.0.0.1` và không yêu cầu đăng nhập. Vì không có danh tính người dùng, bản này không triển khai tài khoản, vai trò Admin/Pentester/Viewer hoặc phân quyền theo từng user. Thay vào đó, việc xác nhận quyền được ghi ở cấp target, các thao tác được audit với actor `local operator`, và giao diện quản trị chỉ truy cập từ máy đang chạy ứng dụng.

## 2. Nguyên tắc tích hợp Strix

- Strix hiện được gọi qua CLI, không xem Strix như một REST API sẵn có. Backend tạo tiến trình chạy `scripts/run_scan.sh` với các tham số đã được kiểm tra.
- Backend là lớp điều phối: kiểm tra đầu vào và xác nhận quyền ở cấp target, tạo scan record, chạy Strix, đọc log/kết quả và lưu lịch sử.
- Đầu ra chuẩn để hiển thị findings là `vulnerabilities.json`. Log của tiến trình được lưu và hiển thị như log thô; không diễn giải log thành timeline agent nếu chưa có parser/nguồn dữ liệu có cấu trúc.
- Mỗi scan có giới hạn ngân sách và được gắn với actor `local operator`, target, cấu hình, thời gian bắt đầu/kết thúc và trạng thái.
- Chỉ cho chạy target đã lưu và có xác nhận quyền. Checkbox xác nhận là bước ghi nhận ý định, không phải kiểm soát kỹ thuật để chặn mọi truy cập ngoài target.

## 3. Nghiệp vụ được thực hiện

### 3.1. Target và xác nhận quyền

Operator tạo hoặc chọn target, khai báo URL, ghi chú scope và xác nhận có quyền kiểm thử. Backend lưu thời điểm xác nhận. Ghi chú scope được đưa vào instruction của agent, không cưỡng chế allowlist ở tầng mạng.

**Tiêu chí hoàn thành:** URL hợp lệ được lưu; scan bị từ chối nếu target không tồn tại, đã ngưng sử dụng hoặc chưa xác nhận quyền kiểm thử.

### 3.2. Cấu hình và chạy scan

Operator chọn target, chế độ `baseline` hoặc `rag`, mức `quick` / `standard` / `deep`, instruction và ngân sách tối đa. Backend kiểm tra tham số rồi khởi chạy script Strix. Model và thông tin xác thực LLM lấy từ `experiments/.env`, không nhập hoặc trả lại key trong trang scan.

Trạng thái scan được quản lý tối thiểu theo vòng đời: `Queued` → `Running` → `Completed` hoặc `Failed`. Dừng một scan đang chạy chưa nằm trong phiên bản này.

**Tiêu chí hoàn thành:** scan được tạo một lần, gọi đúng script với đúng target/chế độ/mức/ngân sách, lưu exit code và thời gian chạy; không cho chạy trùng scan ngoài chủ đích.

### 3.3. Log thô trong lúc chạy

Backend đọc stdout/stderr của tiến trình Strix, nối vào log của scan và gửi cập nhật cho giao diện. Bản đầu hiển thị log thô theo thứ tự thời gian, có trạng thái đang chạy/hoàn tất/thất bại.

Log có thể chứa URL, dữ liệu request hoặc thông tin nhạy cảm. Không hiển thị key LLM; giao diện chỉ bind loopback và áp dụng che dữ liệu nhạy cảm khi nhận diện được.

**Không cam kết trong phạm vi này:** phần trăm tiến độ, phase chính xác, cây agent, danh sách HTTP request chuẩn hóa, token/chi phí realtime, hoặc gửi instruction vào agent đang chạy.

### 3.4. Findings sau khi hoàn tất

Khi tiến trình kết thúc, backend đọc `vulnerabilities.json` của đúng thư mục run và hiển thị danh sách finding. Trường hiển thị gồm title, severity, CWE, method/endpoint, description, evidence, PoC, impact, confidence, remediation và reference nếu có trong dữ liệu Strix.

Finding là kết quả do agent báo cáo, cần chuyên gia xác minh trước khi xem là lỗ hổng đã xác nhận. Không tự suy ra trường thiếu trong artifact.

**Tiêu chí hoàn thành:** chỉ gắn kết quả của đúng run; hiển thị trạng thái không có finding khi danh sách rỗng; xử lý được trường tùy chọn hoặc thiếu.

### 3.5. Báo cáo HTML, JSON và Markdown

Operator cục bộ có thể xuất báo cáo chứa thông tin target, thời điểm, cấu hình scan, tổng số finding theo severity và chi tiết findings. JSON giữ dữ liệu có cấu trúc để tích hợp tiếp; HTML phục vụ đọc/chia sẻ; Markdown thuận tiện cho tài liệu kỹ thuật.

**Chưa bao gồm:** PDF, SARIF, tùy biến template nâng cao, lọc finding theo trạng thái triage.

### 3.6. Lịch sử scan

Operator cục bộ xem danh sách scan. Mỗi bản ghi có target, actor cố định, nguồn chạy, chế độ, mức scan, thời điểm, trạng thái, thời lượng, ngân sách và số finding theo severity khi đã hoàn tất. Hỗ trợ mở lại log, findings và báo cáo của scan cũ.

**Tiêu chí hoàn thành:** scan mới vẫn được ghi nhận sau khi khởi động lại ứng dụng; không phụ thuộc riêng vào tiến trình web đang chạy. Lịch sử được lưu trong cơ sở dữ liệu hoặc kho lưu trữ bền vững, không chỉ giữ trong RAM hay dựa vào danh sách thư mục.

### 3.7. Quản trị cục bộ

Không có đăng nhập hoặc user role. Ứng dụng chỉ bind loopback (`127.0.0.1`); mọi người dùng trên máy đang chạy server được xem và quản lý target, scan, lịch và audit. Việc xác nhận quyền kiểm thử được lưu kèm target. Nếu triển khai nhiều người dùng hoặc mở server ra mạng, cần bổ sung xác thực và phân quyền trước khi bật truy cập đó.

API key/model credentials tiếp tục lấy từ cấu hình bí mật phía server; không ghi vào audit log, giao diện, hoặc báo cáo.

### 3.8. Audit log

Ghi các hành động quan trọng: tạo/sửa/disable target, xác nhận quyền kiểm thử, tạo scan, tạo/xóa lịch, xuất báo cáo, thông báo và sự kiện backend khởi động lại. Mỗi sự kiện ghi actor cố định `local operator`, thời gian, hành động, đối tượng và kết quả; không lưu secret hoặc nội dung nhạy cảm của request.

Audit log chỉ đọc trên giao diện. Bản ghi không được sửa/xóa qua giao diện quản trị thông thường.

### 3.9. Lịch quét và thông báo

Operator cục bộ tạo lịch chạy một cấu hình scan đã lưu: chạy một lần theo thời điểm hẹn hoặc lặp theo chu kỳ được hỗ trợ. Scheduler tạo một scan record như thao tác chạy thủ công; thực thi qua cùng adapter Strix CLI, kiểm tra target còn hoạt động, đã xác nhận quyền và áp dụng ngân sách tại thời điểm chạy.

Thông báo được gửi khi scan hoàn tất/thất bại hoặc khi có finding Critical/High. Bản đầu hỗ trợ một kênh cấu hình được, chẳng hạn email hoặc webhook. Thông báo chỉ chứa metadata và liên kết tới kết quả; không gửi API key, cookie hay toàn bộ request/response.

## 4. Trạng thái và lưu trữ tối thiểu

Mỗi scan cần lưu:

- ID, target, actor `local operator`, nguồn chạy (thủ công/lịch), chế độ, scan mode, instruction và ngân sách.
- Trạng thái, thời điểm tạo/bắt đầu/kết thúc, exit code và thông báo lỗi đã được làm sạch secret.
- Đường dẫn/định danh artifacts của run, log, findings và các báo cáo đã tạo.
- Thống kê finding theo severity sau khi có kết quả.

Lưu trữ target, scan, lịch, cấu hình lịch và audit log trong SQLite bền vững. File artifact cần được liên kết với scan ID.

## 5. Ngoài phạm vi quyết định này

Các nghiệp vụ sau chưa làm trong đợt này:

- Request Inspector có replay, xem raw request/response và lịch sử HTTP đầy đủ.
- Cây agent, phase timeline có cấu trúc, token/chi phí realtime và điều khiển pause/resume/gửi chỉ dẫn giữa scan.
- Sitemap/attack surface chuẩn hóa.
- Triage workflow, gán người xử lý, replay PoC và retest riêng một finding.
- So sánh hai scan theo trạng thái mới/đã sửa/còn tồn tại.
- PDF/SARIF, tích hợp SSO/đa tổ chức, nhiều kênh thông báo và retention tùy biến.

Các mục này có thể xem xét sau khi xác minh artifact/API thực tế của phiên bản Strix đang dùng và hoàn tất adapter thu thập dữ liệu.

## 6. Thứ tự triển khai và trạng thái thực hiện

Đến nay, toàn bộ 4 giai đoạn đã được hoàn thành:

1. **Nền tảng quản lý:** Target, xác nhận quyền, lưu scan và audit log cục bộ. *(Trạng thái: ĐÃ HOÀN THÀNH - `targets`, `audit` table, API POST/GET/PUT/DELETE targets)*
2. **Luồng scan:** Tạo scan, gọi CLI Strix qua wrapper an toàn, cập nhật trạng thái vòng đời (Queued -> Running -> Completed/Failed), streaming/polling log thô, đọc findings `vulnerabilities.json` và xuất báo cáo HTML/JSON/Markdown. *(Trạng thái: ĐÃ HOÀN THÀNH - `web/app.py`, `web/app.js`, `web/index.html`, `web/styles.css`)*
3. **Lịch và thông báo:** Scheduler nền chạy luồng riêng kiểm tra mỗi 15s (hỗ trợ interval và một lần 'once'), kiểm tra lại điều kiện target & quyền trước khi kích hoạt scan, gửi thông báo HTTPS webhook khi hoàn tất/thất bại hoặc có finding Critical/High. *(Trạng thái: ĐÃ HOÀN THÀNH)*
4. **Hoàn thiện vận hành:** Host header / Origin validation (chỉ loopback `127.0.0.1` / `localhost`), CSP & bảo mật header, log secret scrubbing (redact token/key), phục hồi trạng thái scan dở dang khi backend khởi động lại. *(Trạng thái: ĐÃ HOÀN THÀNH)*

## 7. Tiêu chí nghiệm thu tổng thể

- [x] Ứng dụng chỉ lắng nghe trên loopback (`127.0.0.1:8765`); target yêu cầu xác nhận quyền trước khi scan.
- [x] Mỗi scan thủ công và theo lịch đều tạo lịch sử bền vững (SQLite WAL), có trạng thái cuối và liên kết đúng artifacts.
- [x] Log thô được cập nhật định kỳ trong khi Strix chạy; lỗi CLI được thể hiện rõ mà không làm lộ secret.
- [x] Findings và báo cáo lấy từ đúng `vulnerabilities.json` của scan; báo cáo tải được ở HTML, JSON và Markdown.
- [x] Mọi thao tác quản trị/quyền/scan quan trọng có audit event với actor `local operator`.
- [x] Lịch quét gọi cùng quy trình Strix và kiểm tra lại quyền, ngân sách trước khi chạy.
- [x] Thông báo chỉ gửi sau sự kiện hoàn tất/thất bại hoặc có Critical/High và không chứa thông tin xác thực.

## 8. Hướng dẫn chạy và kiểm thử

### 8.1. Khởi động Web Server
Chạy trực tiếp backend Python tích hợp sẵn static web:
```bash
python web/app.py
```
Hoặc trong WSL/Linux:
```bash
python3 web/app.py
```
- Server sẽ lắng nghe tại: `http://127.0.0.1:8765`
- Database SQLite lưu tại: `web/data/strix_web.sqlite3`
- Logs & Reports lưu tại: `web/data/logs/` và `web/data/reports/`

### 8.2. Kịch bản kiểm thử các tính năng

1. **Kiểm tra Target & Scope:**
   - Vào tab **Target**, nhập tên và Base URL (ví dụ: `http://localhost:3000` cho Juice Shop hoặc `http://localhost:8080` cho DVWA).
   - Điền ghi chú scope. Check vào ô *"Tôi sở hữu target hoặc được ủy quyền kiểm thử."* rồi ấn **Lưu target**.
   - Kiểm tra danh sách hiển thị target vừa tạo. Thử sửa (nút *Sửa*) hoặc ngưng sử dụng (*Ngưng dùng*).

2. **Kiểm tra Quét bảo mật (Scan flow):**
   - Vào tab **Quét bảo mật**, chọn target vừa tạo.
   - Chọn chế độ: `Knowledge Base · RAG` hoặc `Baseline`.
   - Chọn độ sâu: `Quick` / `Standard` / `Deep`.
   - Nhập ngân sách USD (ví dụ `1.5`) và instruction kiểm thử.
   - Bắt buộc tick xác nhận quyền kiểm thử trước khi bấm **Bắt đầu scan**.
   - Quan sát panel **Live monitor**: xem log thô cuộn tự động, trạng thái chuyển từ `QUEUED` sang `RUNNING`.
   - Khi hoàn tất, xem bảng tóm tắt rủi ro (Risk Summary) và chi tiết từng Finding.
   - Bấm các nút **Tải HTML**, **Tải JSON**, **Tải Markdown** để kiểm tra xuất báo cáo.

3. **Kiểm tra Lịch sử (History):**
   - Vào tab **Lịch sử scan**, kiểm tra lượt scan vừa tạo đã được lưu bền vững.
   - Bấm nút **Mở kết quả** tại một lượt scan cũ để xem lại log và findings.

4. **Kiểm tra Lịch quét tự động (Scheduler):**
   - Vào tab **Lịch quét**, chọn target, chế độ và chọn kiểu lịch: *Lặp lại theo chu kỳ* hoặc *Chạy một lần*.
   - Tạo lịch và kiểm tra trạng thái kích hoạt.

5. **Kiểm tra Audit Log:**
   - Vào tab **Audit log**, kiểm tra các bản ghi audit ghi nhận đầy đủ các thao tác: tạo target, xác nhận quyền, đưa scan vào queue, xuất report... với actor `local operator`.

6. **Kiểm tra Cấu hình (Settings):**
   - Vào tab **Cấu hình**, kiểm tra trạng thái file `experiments/.env`, trạng thái Webhook và số scan đang chạy.
