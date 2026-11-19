/* =============================================================================
 * STRIX WEB PENTEST — app.js
 * Vanilla JS, no framework, no CDN.
 * Backend: http://127.0.0.1:8765
 * ============================================================================= */

'use strict';

// =============================================================================
// SECTION: Helpers
// =============================================================================

/** Shorthand querySelector */
const $ = (sel, root = document) => root.querySelector(sel);

/** Escape HTML to prevent XSS */
function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Async fetch wrapper.
 * Returns parsed JSON by default; pass {raw:true} to get the Response.
 * Throws Error if response is not ok.
 */
async function api(path, opts = {}) {
  const { raw = false, ...fetchOpts } = opts;
  const res = await fetch(path, fetchOpts);
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { const j = await res.json(); msg = j.error || j.message || msg; } catch (_) { /* ignore */ }
    throw new Error(msg);
  }
  if (raw) return res;
  return res.json();
}

// =============================================================================
// SECTION: State
// =============================================================================

const state = {
  view: 'scan',
  targets: [],
  scans: [],
  schedules: [],
  activeScan: null,
  pollTimer: null,
};

// =============================================================================
// SECTION: Flash notifications
// =============================================================================

let _flashTimer = null;

/**
 * Show a flash message at the top.
 * @param {string} msg
 * @param {boolean} bad — true = error style
 */
function flash(msg, bad = false) {
  const el = $('#flash');
  if (!el) return;
  el.textContent = msg;
  el.classList.toggle('error', bad);
  el.removeAttribute('hidden');
  if (_flashTimer) clearTimeout(_flashTimer);
  _flashTimer = setTimeout(() => { el.setAttribute('hidden', ''); }, 4500);
}

// =============================================================================
// SECTION: Navigation
// =============================================================================

const PAGE_TITLES = {
  scan: 'Scan',
  history: 'Lịch sử Scan',
  targets: 'Quản lý Targets',
  schedules: 'Lịch Scan',
  audit: 'Audit Log',
  settings: 'Cài đặt',
};

function navigate(view) {
  state.view = view;

  // Toggle view sections: support both id="view-{name}" and data-view="{name}"
  document.querySelectorAll('.view').forEach(section => {
    const isTarget = section.id === `view-${view}` || section.dataset.view === view;
    if (isTarget) {
      section.removeAttribute('hidden');
    } else {
      section.setAttribute('hidden', '');
    }
  });

  // Update nav buttons: support data-view and data-nav
  document.querySelectorAll('#nav button').forEach(btn => {
    const v = btn.dataset.view || btn.dataset.nav;
    btn.classList.toggle('active', v === view);
  });

  // Update page title
  const titleEl = $('#pageTitle');
  if (titleEl) titleEl.textContent = PAGE_TITLES[view] || view;

  // Load data for view
  switch (view) {
    case 'scan':      loadTargets(); break;
    case 'history':   loadHistory(); break;
    case 'targets':   loadTargets(); break;
    case 'schedules': loadSchedules(); break;
    case 'audit':     loadAudit(); break;
    case 'settings':  loadSettings(); break;
  }
}

// =============================================================================
// SECTION: Date/Time Formatting
// =============================================================================

/** Format ISO timestamp to Vietnamese locale string */
function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('vi-VN', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch (_) { return iso; }
}

/** Format seconds to hh:mm:ss or mm:ss */
function fmtDuration(secs) {
  if (!secs && secs !== 0) return '—';
  const s = Math.round(secs);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}g ${String(m).padStart(2, '0')}p ${String(sec).padStart(2, '0')}s`;
  return `${String(m).padStart(2, '0')}p ${String(sec).padStart(2, '0')}s`;
}

// =============================================================================
// SECTION: Severity badge
// =============================================================================

function severityBadge(sev) {
  const s = (sev || 'info').toLowerCase();
  return `<span class="badge ${esc(s)}">${esc(sev || 'info')}</span>`;
}

// =============================================================================
// SECTION: loadTargets
// =============================================================================

async function loadTargets() {
  try {
    const targets = await api('/api/targets');
    state.targets = targets;

    // Populate #scanTarget select (active + authorized only)
    const scanSel = $('#scanTarget');
    if (scanSel) {
      const prevVal = scanSel.value;
      // keep placeholder
      while (scanSel.options.length > 1) scanSel.remove(1);
      targets.filter(t => t.active && t.authorized).forEach(t => {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = `${t.name} — ${t.base_url}`;
        scanSel.appendChild(opt);
      });
      scanSel.value = prevVal;
    }

    // Populate #scheduleTarget select (active + authorized only)
    const schedSel = $('#scheduleTarget');
    if (schedSel) {
      const prevVal = schedSel.value;
      while (schedSel.options.length > 1) schedSel.remove(1);
      targets.filter(t => t.active && t.authorized).forEach(t => {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = `${t.name} — ${t.base_url}`;
        schedSel.appendChild(opt);
      });
      schedSel.value = prevVal;
    }

    // Render #targetList cards
    const listEl = $('#targetList');
    if (listEl) {
      listEl.innerHTML = '';
      if (targets.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'muted';
        empty.textContent = 'Chưa có target nào.';
        listEl.appendChild(empty);
      } else {
        targets.forEach(t => {
          const card = buildTargetCard(t);
          listEl.appendChild(card);
        });
      }
    }

    // Update #targetCount
    const countEl = $('#targetCount');
    if (countEl) countEl.textContent = targets.length;

  } catch (err) {
    flash(`Lỗi tải targets: ${err.message}`, true);
  }
}

function buildTargetCard(t) {
  const card = document.createElement('div');
  card.className = `target-card${t.active ? '' : ' disabled'}`;
  card.dataset.targetId = t.id;

  // Header row
  const header = document.createElement('div');
  header.className = 'card-header';

  const nameEl = document.createElement('span');
  nameEl.className = 'card-title';
  nameEl.textContent = t.name;

  const badges = document.createElement('span');
  badges.className = 'card-badges';
  if (t.authorized) {
    const ab = document.createElement('span');
    ab.className = 'badge info';
    ab.textContent = 'Authorized';
    badges.appendChild(ab);
  }
  if (!t.active) {
    const db = document.createElement('span');
    db.className = 'badge low';
    db.textContent = 'Disabled';
    badges.appendChild(db);
  }

  header.appendChild(nameEl);
  header.appendChild(badges);

  // Body
  const body = document.createElement('div');
  body.className = 'card-body';

  const url = document.createElement('p');
  url.className = 'card-url';
  url.textContent = t.base_url;

  const scope = document.createElement('p');
  scope.className = 'card-scope muted';
  scope.textContent = t.scope_note || '';

  const meta = document.createElement('p');
  meta.className = 'card-meta muted';
  meta.textContent = `Tạo lúc: ${fmtDate(t.created_at)}`;

  body.appendChild(url);
  if (t.scope_note) body.appendChild(scope);
  body.appendChild(meta);

  // Actions
  const actions = document.createElement('div');
  actions.className = 'card-actions';

  const editBtn = document.createElement('button');
  editBtn.className = 'btn btn-sm';
  editBtn.textContent = 'Sửa';
  editBtn.dataset.targetEdit = t.id;

  const disableBtn = document.createElement('button');
  disableBtn.className = 'btn btn-sm btn-danger';
  disableBtn.textContent = t.active ? 'Vô hiệu hóa' : 'Đã vô hiệu';
  disableBtn.dataset.targetDisable = t.id;
  disableBtn.disabled = !t.active;

  actions.appendChild(editBtn);
  actions.appendChild(disableBtn);

  card.appendChild(header);
  card.appendChild(body);
  card.appendChild(actions);
  return card;
}

// =============================================================================
// SECTION: loadHistory
// =============================================================================

async function loadHistory() {
  try {
    const scans = await api('/api/scans');
    state.scans = scans;

    const tbody = $('#historyRows');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (scans.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.className = 'muted text-center';
      td.textContent = 'Chưa có lịch sử scan.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    scans.forEach(scan => {
      const tr = buildHistoryRow(scan);
      tbody.appendChild(tr);
    });

  } catch (err) {
    flash(`Lỗi tải lịch sử: ${err.message}`, true);
  }
}

function buildHistoryRow(scan) {
  const tr = document.createElement('tr');

  // Target
  const tdTarget = document.createElement('td');
  tdTarget.textContent = scan.target_name || '—';

  // Mode/Depth
  const tdMode = document.createElement('td');
  tdMode.textContent = `${scan.mode || '—'} / ${scan.scan_mode || '—'}`;

  // Time
  const tdTime = document.createElement('td');
  tdTime.textContent = fmtDate(scan.created_at);

  // Duration
  const tdDur = document.createElement('td');
  tdDur.textContent = scan.duration_seconds != null ? fmtDuration(scan.duration_seconds) : '—';

  // Status
  const tdStatus = document.createElement('td');
  const statusBadge = document.createElement('span');
  const statusClass = statusToClass(scan.status);
  statusBadge.className = `badge ${statusClass}`;
  statusBadge.textContent = scan.status || '—';
  tdStatus.appendChild(statusBadge);

  // Findings count with severity breakdown
  const tdFindings = document.createElement('td');
  if (scan.status === 'Completed' && Array.isArray(scan.findings)) {
    const counts = countSeverities(scan.findings);
    tdFindings.innerHTML = buildSeveritySummaryHtml(counts);
  } else if (scan.finding_count != null) {
    tdFindings.textContent = scan.finding_count;
  } else {
    tdFindings.textContent = '—';
  }

  // Actions
  const tdAction = document.createElement('td');
  const openBtn = document.createElement('button');
  openBtn.className = 'btn btn-sm';
  openBtn.textContent = 'Mở kết quả';
  openBtn.dataset.openScan = scan.id;
  tdAction.appendChild(openBtn);

  tr.appendChild(tdTarget);
  tr.appendChild(tdMode);
  tr.appendChild(tdTime);
  tr.appendChild(tdDur);
  tr.appendChild(tdStatus);
  tr.appendChild(tdFindings);
  tr.appendChild(tdAction);
  return tr;
}

function statusToClass(status) {
  switch (status) {
    case 'Completed': return 'info';
    case 'Running':   return 'medium';
    case 'Queued':    return 'low';
    case 'Failed':    return 'high';
    default:          return 'muted';
  }
}

function countSeverities(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  (findings || []).forEach(f => {
    const s = (f.severity || 'info').toLowerCase();
    if (counts[s] !== undefined) counts[s]++;
    else counts.info++;
  });
  return counts;
}

function buildSeveritySummaryHtml(counts) {
  const parts = [];
  if (counts.critical) parts.push(`<span class="badge critical">${esc(String(counts.critical))} C</span>`);
  if (counts.high)     parts.push(`<span class="badge high">${esc(String(counts.high))} H</span>`);
  if (counts.medium)   parts.push(`<span class="badge medium">${esc(String(counts.medium))} M</span>`);
  if (counts.low)      parts.push(`<span class="badge low">${esc(String(counts.low))} L</span>`);
  if (counts.info)     parts.push(`<span class="badge info">${esc(String(counts.info))} I</span>`);
  return parts.length ? parts.join(' ') : '<span class="muted">—</span>';
}

// =============================================================================
// SECTION: loadSchedules
// =============================================================================

async function loadSchedules() {
  try {
    await loadTargets();
    const schedules = await api('/api/schedules');
    state.schedules = schedules;

    const listEl = $('#scheduleList');
    if (!listEl) return;
    listEl.innerHTML = '';

    const countEl = $('#scheduleCount');
    if (countEl) countEl.textContent = schedules.length;

    if (schedules.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'muted';
      empty.textContent = 'Chưa có lịch scan nào.';
      listEl.appendChild(empty);
      return;
    }

    schedules.forEach(sched => {
      const card = buildScheduleCard(sched);
      listEl.appendChild(card);
    });

  } catch (err) {
    flash(`Lỗi tải lịch: ${err.message}`, true);
  }
}

function buildScheduleCard(sched) {
  const card = document.createElement('div');
  card.className = `schedule-card${sched.active ? '' : ' disabled'}`;

  const header = document.createElement('div');
  header.className = 'card-header';

  const name = document.createElement('span');
  name.className = 'card-title';
  name.textContent = sched.target_name || `Target #${sched.target_id}`;

  const typeBadge = document.createElement('span');
  typeBadge.className = 'badge info';
  typeBadge.textContent = sched.schedule_type === 'interval' ? `Mỗi ${sched.interval_hours}h` : 'Một lần';

  header.appendChild(name);
  header.appendChild(typeBadge);

  const body = document.createElement('div');
  body.className = 'card-body';

  const urlP = document.createElement('p');
  urlP.className = 'muted';
  urlP.textContent = sched.target_url || '';

  const modeP = document.createElement('p');
  modeP.textContent = `Chế độ: ${sched.mode || '—'} / ${sched.scan_mode || '—'}`;

  const nextP = document.createElement('p');
  nextP.className = 'muted';
  nextP.textContent = `Lần chạy kế: ${fmtDate(sched.next_run_at)}`;

  const lastP = document.createElement('p');
  lastP.className = 'muted';
  lastP.textContent = `Lần chạy cuối: ${fmtDate(sched.last_run_at)}`;

  body.appendChild(urlP);
  body.appendChild(modeP);
  body.appendChild(nextP);
  body.appendChild(lastP);

  const actions = document.createElement('div');
  actions.className = 'card-actions';

  const delBtn = document.createElement('button');
  delBtn.className = 'btn btn-sm btn-danger';
  delBtn.textContent = 'Xóa lịch';
  delBtn.dataset.scheduleDelete = sched.id;
  actions.appendChild(delBtn);

  card.appendChild(header);
  card.appendChild(body);
  card.appendChild(actions);
  return card;
}

// =============================================================================
// SECTION: loadAudit
// =============================================================================

async function loadAudit() {
  try {
    const events = await api('/api/audit');

    const tbody = $('#auditRows');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!events || events.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'muted text-center';
      td.textContent = 'Không có sự kiện nào.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    events.forEach(ev => {
      const tr = document.createElement('tr');

      const cells = [
        fmtDate(ev.created_at),
        ev.actor || '—',
        ev.action || '—',
        ev.object_type ? `${ev.object_type} #${ev.object_id}` : '—',
        ev.result || '—',
        ev.details ? JSON.stringify(ev.details) : '—',
      ];

      cells.forEach(text => {
        const td = document.createElement('td');
        td.textContent = text;
        tr.appendChild(td);
      });

      tbody.appendChild(tr);
    });

  } catch (err) {
    flash(`Lỗi tải audit log: ${err.message}`, true);
  }
}

// =============================================================================
// SECTION: loadSettings
// =============================================================================

async function loadSettings() {
  try {
    const settings = await api('/api/settings');

    const infoEl = $('#settingsInfo');
    if (!infoEl) return;
    infoEl.innerHTML = '';

    const rows = [
      ['Strix cấu hình', settings.strix_configured ? '✅ Đã cấu hình' : '❌ Chưa cấu hình'],
      ['Webhook', settings.webhook_enabled ? '✅ Bật' : '❌ Tắt'],
      ['Active scans', String(settings.active_scans ?? '—')],
      ['Chế độ local only', settings.local_only ? '✅ Có' : '❌ Không'],
    ];

    rows.forEach(([label, value]) => {
      const row = document.createElement('div');
      row.className = 'settings-row';

      const lbl = document.createElement('span');
      lbl.className = 'settings-label';
      lbl.textContent = label;

      const val = document.createElement('span');
      val.className = 'settings-value';
      val.textContent = value;

      row.appendChild(lbl);
      row.appendChild(val);
      infoEl.appendChild(row);
    });

    const note = document.createElement('p');
    note.className = 'muted settings-note';
    note.textContent = 'API key và cấu hình bảo mật được lấy từ experiments/.env, không hiển thị trong UI.';
    infoEl.appendChild(note);

  } catch (err) {
    flash(`Lỗi tải cài đặt: ${err.message}`, true);
  }
}

// =============================================================================
// SECTION: showScan
// =============================================================================

async function showScan(scanId, live = false) {
  try {
    const scan = await api(`/api/scans/${scanId}`);
    state.activeScan = scan;

    // Show monitor, hide empty state
    const monitorEl = $('#monitor');
    const emptyEl = $('#emptyMonitor');
    if (monitorEl) monitorEl.removeAttribute('hidden');
    if (emptyEl) emptyEl.setAttribute('hidden', '');

    // Update header fields
    setText('#currentTarget', scan.target_name || scan.target_url || `Scan #${scan.id}`);
    setText('#currentElapsed', scan.duration_seconds != null ? fmtDuration(scan.duration_seconds) : (scan.started_at ? 'Đang chạy…' : '—'));
    setText('#scanState', scan.status || '—');

    // State badge
    const stateBadge = $('#stateBadge');
    if (stateBadge) {
      stateBadge.textContent = scan.status || '—';
      stateBadge.className = `badge ${statusToClass(scan.status)}`;
    }

    // Pulse indicator
    const pulseEl = $('.pulse');
    const isLive = scan.status === 'Running' || scan.status === 'Queued';
    if (pulseEl) pulseEl.classList.toggle('active', isLive);

    // Live log
    const liveLog = $('#liveLog');
    if (liveLog) {
      liveLog.textContent = scan.logs || 'Chưa có log.';
      liveLog.scrollTop = liveLog.scrollHeight;
    }

    // Log line count
    const logCount = $('#logCount');
    if (logCount) {
      const lines = scan.logs ? scan.logs.split('\n').length : 0;
      logCount.textContent = `${lines} dòng`;
    }

    // Result area
    const resultArea = $('#resultArea');
    if (scan.status === 'Completed') {
      renderReport(scan.findings, scan);
    } else if (scan.status === 'Failed') {
      if (resultArea) {
        resultArea.innerHTML = '';
        const notice = document.createElement('div');
        notice.className = 'error-notice';
        const icon = document.createElement('p');
        icon.textContent = '❌ Scan thất bại';
        icon.className = 'error-title';
        const msg = document.createElement('p');
        msg.className = 'muted';
        msg.textContent = scan.error || 'Không có thông tin lỗi.';
        notice.appendChild(icon);
        notice.appendChild(msg);
        resultArea.appendChild(notice);
      }
    } else {
      // Running or Queued — clear results
      if (resultArea) resultArea.innerHTML = '';
    }

    // Navigate to scan view if not a live poll
    if (!live) {
      navigate('scan');
    }

  } catch (err) {
    flash(`Lỗi tải scan: ${err.message}`, true);
  }
}

function setText(selector, text) {
  const el = $(selector);
  if (el) el.textContent = text;
}

// =============================================================================
// SECTION: renderReport
// =============================================================================

function renderReport(findings, scan) {
  const resultArea = $('#resultArea');
  if (!resultArea) return;
  resultArea.innerHTML = '';

  if (!Array.isArray(findings)) {
    const msg = document.createElement('p');
    msg.className = 'muted';
    msg.textContent = 'Không tìm thấy vulnerabilities.json hoặc không có findings.';
    resultArea.appendChild(msg);
    return;
  }

  // Count by severity
  const counts = countSeverities(findings);

  // --- Risk Summary ---
  const summarySection = document.createElement('div');
  summarySection.className = 'report-summary';

  const summaryTitle = document.createElement('h3');
  summaryTitle.textContent = 'Tóm tắt rủi ro';
  summarySection.appendChild(summaryTitle);

  const summaryCards = document.createElement('div');
  summaryCards.className = 'summary-cards';
  ['critical', 'high', 'medium', 'low', 'info'].forEach(sev => {
    const card = document.createElement('div');
    card.className = `summary-card ${sev}`;

    const num = document.createElement('span');
    num.className = 'summary-count';
    num.textContent = counts[sev];

    const label = document.createElement('span');
    label.className = 'summary-label';
    label.textContent = sev.charAt(0).toUpperCase() + sev.slice(1);

    card.appendChild(num);
    card.appendChild(label);
    summaryCards.appendChild(card);
  });
  summarySection.appendChild(summaryCards);
  resultArea.appendChild(summarySection);

  // --- Download Report Buttons ---
  const dlSection = document.createElement('div');
  dlSection.className = 'report-download';

  const dlTitle = document.createElement('h3');
  dlTitle.textContent = 'Tải báo cáo';
  dlSection.appendChild(dlTitle);

  const dlBtns = document.createElement('div');
  dlBtns.className = 'download-buttons';
  [['html', 'HTML'], ['json', 'JSON'], ['md', 'Markdown']].forEach(([fmt, label]) => {
    const btn = document.createElement('button');
    btn.className = 'btn btn-sm';
    btn.textContent = `⬇ ${label}`;
    btn.dataset.report = fmt;
    btn.dataset.scanId = scan.id;
    dlBtns.appendChild(btn);
  });
  dlSection.appendChild(dlBtns);
  resultArea.appendChild(dlSection);

  // --- Findings ---
  if (findings.length === 0) {
    const noFindings = document.createElement('p');
    noFindings.className = 'muted';
    noFindings.textContent = 'Không tìm thấy vulnerability nào.';
    resultArea.appendChild(noFindings);
    return;
  }

  const findingsSection = document.createElement('div');
  findingsSection.className = 'findings-section';

  const findingsTitle = document.createElement('h3');
  findingsTitle.textContent = `Chi tiết Findings (${findings.length})`;
  findingsSection.appendChild(findingsTitle);

  findings.forEach((f, idx) => {
    const card = buildFindingCard(f, idx);
    findingsSection.appendChild(card);
  });

  resultArea.appendChild(findingsSection);
}

function buildFindingCard(f, idx) {
  const card = document.createElement('div');
  card.className = 'finding-card';
  card.dataset.findingIdx = idx;
  card.style.cursor = 'pointer';

  const header = document.createElement('div');
  header.className = 'finding-header';

  const title = document.createElement('span');
  title.className = 'finding-title';
  title.textContent = f.title || 'Untitled Finding';

  const sev = (f.severity || 'info').toLowerCase();
  const badge = document.createElement('span');
  badge.className = `badge ${sev}`;
  badge.textContent = f.severity || 'info';

  header.appendChild(title);
  header.appendChild(badge);
  card.appendChild(header);

  const preview = document.createElement('div');
  preview.className = 'finding-preview';

  if (f.endpoint || f.url) {
    const ep = document.createElement('p');
    ep.className = 'finding-endpoint muted';
    const method = f.method ? `[${f.method}] ` : '';
    ep.textContent = `${method}${f.endpoint || f.url}`;
    preview.appendChild(ep);
  }
  if (f.cwe) {
    const cwe = document.createElement('p');
    cwe.className = 'muted';
    cwe.textContent = `CWE: ${f.cwe}`;
    preview.appendChild(cwe);
  }

  card.appendChild(preview);

  // Click to open modal
  card.addEventListener('click', () => openFindingModal(f));

  return card;
}

// =============================================================================
// SECTION: Finding Modal
// =============================================================================

function openFindingModal(f) {
  // Remove existing modal
  const existing = $('#findingModal');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'findingModal';
  overlay.className = 'modal-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');

  const modal = document.createElement('div');
  modal.className = 'modal';

  // Close button
  const closeBtn = document.createElement('button');
  closeBtn.className = 'modal-close';
  closeBtn.textContent = '✕';
  closeBtn.setAttribute('aria-label', 'Đóng');
  closeBtn.addEventListener('click', closeModal);

  // Title
  const title = document.createElement('h2');
  title.className = 'modal-title';
  title.textContent = f.title || 'Finding Detail';

  // Severity badge
  const sev = (f.severity || 'info').toLowerCase();
  const badge = document.createElement('span');
  badge.className = `badge ${sev} modal-badge`;
  badge.textContent = f.severity || 'info';

  modal.appendChild(closeBtn);
  modal.appendChild(title);
  modal.appendChild(badge);

  // Fields
  const fields = [
    ['Endpoint', f.endpoint || f.url],
    ['Method', f.method],
    ['CWE', f.cwe],
    ['Confidence', f.confidence],
    ['Mô tả', f.description],
    ['Evidence', f.evidence],
    ['PoC', f.poc || f.proof_of_concept],
    ['Impact', f.impact],
    ['Remediation', f.remediation || f.solution],
    ['References', Array.isArray(f.references) ? f.references.join('\n') : (f.references || f.reference)],
  ];

  fields.forEach(([label, value]) => {
    if (!value) return;
    const section = document.createElement('div');
    section.className = 'modal-field';

    const lbl = document.createElement('strong');
    lbl.textContent = label;

    const val = document.createElement('pre');
    val.className = 'modal-value';
    val.textContent = value;

    section.appendChild(lbl);
    section.appendChild(val);
    modal.appendChild(section);
  });

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  // Close on overlay click
  overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });

  // ESC to close
  document.addEventListener('keydown', handleModalEsc);
}

function handleModalEsc(e) {
  if (e.key === 'Escape') closeModal();
}

function closeModal() {
  const modal = $('#findingModal');
  if (modal) modal.remove();
  document.removeEventListener('keydown', handleModalEsc);
}

// =============================================================================
// SECTION: pollActive
// =============================================================================

async function pollActive() {
  try {
    const activeScans = await api('/api/scans?active=1');

    if (Array.isArray(activeScans) && activeScans.length > 0) {
      const scan = activeScans[0];

      // If we're on the scan view, update live
      if (state.view === 'scan') {
        await showScan(scan.id, true);
      }

      state.activeScan = scan;
    } else {
      // No active scans — if we were showing a live scan, do a final refresh
      if (state.activeScan && (state.activeScan.status === 'Running' || state.activeScan.status === 'Queued')) {
        const prevId = state.activeScan.id;
        state.activeScan = null;
        if (state.view === 'scan') {
          await showScan(prevId, true);
        }
      }
    }
  } catch (_) {
    // Silent fail for polling — don't spam flash
  }
}

// =============================================================================
// SECTION: Report Download
// =============================================================================

async function downloadReport(scanId, format) {
  try {
    const res = await api(`/api/scans/${scanId}/report?format=${format}`, { raw: true });
    const blob = await res.blob();
    const ext = format === 'md' ? 'md' : format;
    const filename = `strix-report-${scanId}.${ext}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  } catch (err) {
    flash(`Lỗi tải report: ${err.message}`, true);
  }
}

// =============================================================================
// SECTION: Event Listeners
// =============================================================================

function setupEventListeners() {

  // --- Nav click ---
  const nav = $('#nav');
  if (nav) {
    nav.addEventListener('click', (e) => {
      const btn = e.target.closest('button');
      if (btn) {
        const v = btn.dataset.view || btn.dataset.nav;
        if (v) navigate(v);
      }
    });
  }

  // --- data-goto ---
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-goto]');
    if (btn) navigate(btn.dataset.goto);
  });

  // --- data-open-scan ---
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-open-scan]');
    if (btn) showScan(btn.dataset.openScan);
  });

  // --- data-target-disable ---
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-target-disable]');
    if (!btn || btn.disabled) return;
    const id = btn.dataset.targetDisable;
    if (!confirm('Bạn có chắc muốn vô hiệu hóa target này không?')) return;
    try {
      await api(`/api/targets/${id}`, { method: 'DELETE' });
      flash('Đã vô hiệu hóa target.');
      await loadTargets();
    } catch (err) {
      flash(`Lỗi: ${err.message}`, true);
    }
  });

  // --- data-target-edit ---
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-target-edit]');
    if (!btn) return;
    const id = btn.dataset.targetEdit;
    const target = state.targets.find(t => String(t.id) === String(id));
    if (!target) return;

    const name = prompt('Tên target:', target.name);
    if (name === null) return;
    const base_url = prompt('URL cơ sở:', target.base_url);
    if (base_url === null) return;
    const scope_note = prompt('Ghi chú phạm vi:', target.scope_note || '');
    if (scope_note === null) return;
    if (!confirm(`Xác nhận cập nhật target "${name}"?`)) return;

    try {
      await api(`/api/targets/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, base_url, scope_note }),
      });
      flash('Đã cập nhật target.');
      await loadTargets();
    } catch (err) {
      flash(`Lỗi: ${err.message}`, true);
    }
  });

  // --- data-schedule-delete ---
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-schedule-delete]');
    if (!btn) return;
    const id = btn.dataset.scheduleDelete;
    if (!confirm('Xóa lịch scan này?')) return;
    try {
      await api(`/api/schedules/${id}`, { method: 'DELETE' });
      flash('Đã xóa lịch scan.');
      await loadSchedules();
    } catch (err) {
      flash(`Lỗi: ${err.message}`, true);
    }
  });

  // --- data-report click (download) ---
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-report]');
    if (!btn) return;
    const format = btn.dataset.report;
    const scanId = btn.dataset.scanId || (state.activeScan && state.activeScan.id);
    if (!scanId) { flash('Không xác định được scan ID.', true); return; }
    await downloadReport(scanId, format);
  });

  // --- #targetForm submit ---
  const targetForm = $('#targetForm');
  if (targetForm) {
    targetForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = $('#targetName').value.trim();
      const base_url = $('#targetUrl').value.trim();
      const scope_note = $('#targetScope').value.trim();
      const authorized = $('#targetAuthorized').checked;

      if (!name || !base_url) { flash('Vui lòng điền tên và URL.', true); return; }

      try {
        await api('/api/targets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, base_url, scope_note, authorized }),
        });
        targetForm.reset();
        flash('Đã thêm target mới.');
        await loadTargets();
      } catch (err) {
        flash(`Lỗi: ${err.message}`, true);
      }
    });
  }

  // --- #scanForm submit ---
  const scanForm = $('#scanForm');
  if (scanForm) {
    scanForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const confirmCheck = $('#confirmScan');
      if (!confirmCheck || !confirmCheck.checked) {
        flash('Vui lòng xác nhận bạn được phép scan.', true);
        return;
      }

      const target_id = $('#scanTarget').value;
      if (!target_id) { flash('Vui lòng chọn target.', true); return; }

      const mode = document.querySelector('#scanForm [name="mode"]:checked')?.value
        || ($('#scanModeRag')?.value) || 'baseline';
      const scan_mode = $('#scanDepth')?.value || 'standard';
      const budget = $('#scanBudget')?.value || '';
      const instruction = $('#scanInstruction')?.value || '';

      try {
        const scan = await api('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target_id, mode, scan_mode, budget, instruction, authorized: true }),
        });
        flash('Đã khởi động scan!');
        await showScan(scan.id || scan.scan_id);
      } catch (err) {
        flash(`Lỗi khởi động scan: ${err.message}`, true);
      }
    });
  }

  // --- #scheduleType change ---
  const scheduleType = $('#scheduleType');
  if (scheduleType) {
    scheduleType.addEventListener('change', () => {
      const val = scheduleType.value;
      const intervalField = $('#intervalField');
      const onceField = $('#onceField');
      const hoursInput = $('#scheduleHours');
      const atInput = $('#scheduleAt');

      if (val === 'interval') {
        if (intervalField) intervalField.removeAttribute('hidden');
        if (onceField) onceField.setAttribute('hidden', '');
        if (hoursInput) hoursInput.setAttribute('required', '');
        if (atInput) atInput.removeAttribute('required');
      } else {
        if (intervalField) intervalField.setAttribute('hidden', '');
        if (onceField) onceField.removeAttribute('hidden');
        if (hoursInput) hoursInput.removeAttribute('required');
        if (atInput) atInput.setAttribute('required', '');
      }
    });
  }

  // --- #scheduleForm submit ---
  const scheduleForm = $('#scheduleForm');
  if (scheduleForm) {
    scheduleForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const target_id = $('#scheduleTarget').value;
      if (!target_id) { flash('Vui lòng chọn target.', true); return; }

      const mode = document.querySelector('#scheduleForm [name="scheduleMode"]:checked')?.value
        || ($('#scheduleMode')?.value) || 'baseline';
      const scan_mode = $('#scheduleDepth')?.value || 'standard';
      const schedule_type = $('#scheduleType')?.value || 'interval';
      const interval_hours = schedule_type === 'interval' ? (parseInt($('#scheduleHours')?.value) || 24) : null;
      const scheduled_for = schedule_type === 'once' ? ($('#scheduleAt')?.value || null) : null;
      const budget = $('#scheduleBudget')?.value || '';
      const instruction = $('#scheduleInstruction')?.value || '';

      try {
        await api('/api/schedules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target_id, mode, scan_mode, schedule_type, interval_hours, scheduled_for, budget, instruction }),
        });
        scheduleForm.reset();
        flash('Đã tạo lịch scan.');
        await loadSchedules();
      } catch (err) {
        flash(`Lỗi tạo lịch: ${err.message}`, true);
      }
    });
  }

  // --- #refresh click ---
  const refreshBtn = $('#refresh');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      pollActive();
      switch (state.view) {
        case 'scan':      await loadTargets(); break;
        case 'history':   await loadHistory(); break;
        case 'targets':   await loadTargets(); break;
        case 'schedules': await loadSchedules(); break;
        case 'audit':     await loadAudit(); break;
        case 'settings':  await loadSettings(); break;
      }
    });
  }
}

// =============================================================================
// SECTION: Init
// =============================================================================

function init() {
  setupEventListeners();
  navigate('scan');

  // Initial data loads
  loadTargets();
  loadHistory();
  loadSchedules();
  loadAudit();
  loadSettings();

  // Start polling
  pollActive();
  setInterval(pollActive, 1800);
}

// Boot on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
