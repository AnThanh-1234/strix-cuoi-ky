# Tiến độ đồ án — Strix + Knowledge Base RAG

> Môn: An toàn thông tin · Đồ án
> Cập nhật lần cuối: **13/11/2026**
> Tài liệu liên quan: [KET_QUA.md](KET_QUA.md) (kết quả chi tiết) · [README.md](README.md) (hướng dẫn) · [BAO_CAO_DO_AN.docx](BAO_CAO_DO_AN.docx) (báo cáo nộp)

---

## 1. Tổng quan

| | |
|---|---|
| **Trạng thái chung** | Hạ tầng xong, đang chờ gỡ nghẽn để chạy thực nghiệm chính |
| **Hoàn thành** | ~70% (toàn bộ hệ thống + 1 phần thực nghiệm) |
| **Nghẽn hiện tại** | Key Gemini free tier bị chặn 20 request/ngày → chưa chạy xong ma trận baseline/RAG. **Cần bật billing.** |

Thanh tiến độ:

```
Hạ tầng & lab        ██████████ 100%
Knowledge Base (RAG) ██████████ 100%
Tích hợp vào Strix   ██████████ 100%
Bộ chấm tự động      ██████████ 100%
Thực nghiệm quét     ████░░░░░░  40%  (xong model nhỏ; Gemini bị chặn quota)
So sánh baseline/RAG ░░░░░░░░░░   0%  (chờ model trả phí)
Báo cáo              ███████░░░  70%  (bản nháp .docx xong, chờ số liệu cuối)
```

---

## 2. Công việc đã hoàn thành ✅

| # | Công việc | Ghi chú |
|---|---|---|
| 1 | Docker Engine 29 trong WSL2 (không cần Docker Desktop) | Đã xử lý lỗi iptables legacy |
| 2 | Dựng lab: OWASP Juice Shop (:3000) + DVWA (:8080) | `scripts/lab.sh` |
| 3 | Cài Strix 1.7.0 + sandbox image 5.9 GB | Qua `uv tool` |
| 4 | Xây Knowledge Base: 6112 chunk (OWASP CS + WSTG + CWE) | `rag/build_index.py` |
| 5 | Hybrid search (dense + BM25 + RRF), đánh giá Hit@k/MRR | BM25 tốt nhất: MRR 0.804 |
| 6 | MCP server tích hợp KB vào Strix (mức 2) | `rag/mcp_server.py`, không sửa mã Strix |
| 7 | Hậu xử lý báo cáo bằng RAG (mức 1) | `rag/enrich_report.py` |
| 8 | LLM server mô hình nhỏ trên GPU Kaggle | `scripts/kaggle_llm.sh` + proxy keepalive |
| 9 | Bộ chấm TP/FP tự động (4 lớp + kiểm định giám khảo) | `experiments/auto_label.py` |
| 10 | Chạy 3 lần quét với model nhỏ (qwen3 14B/32B) | Đều 0 finding |
| 11 | Chạy 1 lần quét với Gemini 2.5 Flash | Giải 1/118 challenge, hết quota |
| 12 | Báo cáo Word theo mẫu | `BAO_CAO_DO_AN.docx` |

---

## 3. Đang chờ / bị chặn ⏸️

| Công việc | Lý do chặn | Cần gì để gỡ |
|---|---|---|
| Hoàn thành quét Juice Shop (baseline) | Gemini free tier 20 req/ngày | Bật billing cho key Gemini |
| So sánh chế độ baseline vs RAG | Chưa có baseline đủ finding | Như trên |
| Quét DVWA | Chưa chạy | Như trên |
| Hậu xử lý RAG trên finding thật | Chưa có finding | Như trên |

---

## 4. Việc cần làm tiếp 📋

- [ ] **Bật billing cho key Gemini** (Google AI Studio) — điều kiện bắt buộc
- [ ] Chạy ma trận `{Juice Shop, DVWA} × {baseline, RAG}`, mỗi ô 2 lần
- [ ] Chạy `auto_label.py` + `collect_metrics.py` → precision, recall, kappa
- [ ] Chạy `enrich_report.py` so sánh chất lượng báo cáo có/không RAG
- [ ] Cập nhật Chương 3 của báo cáo với số liệu cuối
- [ ] Chèn sơ đồ kiến trúc (Hình 2.1) vào báo cáo
- [ ] (Tùy chọn) Cải thiện hybrid search: tăng trọng số BM25
- [ ] (Tùy chọn) Tự viết app nhỏ có lỗi mới để test khả năng tìm lỗi chưa biết

---

## 5. Nhật ký

| Ngày | Nội dung |
|---|---|
| 12/11/2026 | Dựng WSL + Docker + lab; cài Strix; xây Knowledge Base 6112 chunk; làm MCP server, enrich, bộ chấm tự động |
| 12/11/2026 | Dựng LLM server Kaggle; quét qwen3:14b (×2) và qwen3:32b → đều 0 finding |
| 13/11/2026 | Quét Gemini 2.5 Flash → giải 1 challenge rồi hết quota free tier; viết KET_QUA.md; viết báo cáo .docx theo mẫu |

---

## 6. Ánh xạ kế hoạch 5 tuần

| Tuần | Kế hoạch | Trạng thái |
|---|---|---|
| 1 | Cài Docker, lab, Strix; chạy thử; vẽ luồng hoạt động | ✅ Xong (sớm hơn kế hoạch) |
| 2 | Xây RAG, vector DB, tích hợp mức 1 | ✅ Xong (sớm hơn kế hoạch) |
| 3 | Thực nghiệm có/không RAG, nhiều model, đo số liệu | ⏳ Đang làm — **bị chặn quota**, đã xong phần model nhỏ |
| 4 | Tích hợp mức 2, test lỗi mới | ✅ Mức 2 xong · ⬜ test lỗi mới chưa làm |
| 5 | Tổng hợp số liệu, viết báo cáo, làm slide | 🟡 Báo cáo nháp xong, chờ số liệu cuối · ⬜ slide |

**Nhận định:** tiến độ nhanh hơn kế hoạch ở hạ tầng (tuần 1–2 và mức 2 của tuần 4 đã xong). Rủi ro duy nhất là nghẽn quota ở tuần 3 — gỡ được ngay khi có model trả phí.
