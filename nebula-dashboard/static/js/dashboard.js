/* nebula-dashboard — dashboard logic */

"use strict";

const REFRESH_INTERVAL_MS = 30_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function el(id) { return document.getElementById(id); }

function fmtTimestamp(iso) {
    if (!iso) return "—";
    try {
        const d = new Date(iso);
        return d.toLocaleString(undefined, {
            year:   "numeric", month:  "2-digit", day:    "2-digit",
            hour:   "2-digit", minute: "2-digit", second: "2-digit",
            hour12: false,
        });
    } catch { return iso; }
}

function timeAgo(iso) {
    if (!iso) return "";
    try {
        const diff = (Date.now() - new Date(iso).getTime()) / 1000;
        if (diff < 60)    return `${Math.round(diff)}s ago`;
        if (diff < 3600)  return `${Math.round(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
        return `${Math.round(diff / 86400)}d ago`;
    } catch { return ""; }
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// ---------------------------------------------------------------------------
// Tool status
// ---------------------------------------------------------------------------

async function fetchStatus() {
    setBannerChecking();
    try {
        const resp = await fetch("/api/status");
        const data = await resp.json();
        renderTools(data.tools);
        renderBanner(data.online_count, data.total_count);
        el("last-updated").textContent = "Updated " + timeAgo(data.checked_at);
    } catch (err) {
        console.error("Status fetch failed:", err);
        el("last-updated").textContent = "Update failed";
    }
}

function setBannerChecking() {
    const banner = el("status-banner");
    banner.innerHTML = `
        <span class="spinner"></span>
        <span class="label">Checking tools&hellip;</span>
    `;
}

function renderBanner(online, total) {
    const banner = el("status-banner");
    let cls = "all-online";
    if (online === 0) cls = "all-offline";
    else if (online < total) cls = "some-offline";

    banner.innerHTML = `
        <span class="count ${cls}">${online} / ${total}</span>
        <span class="label">tools online</span>
    `;
}

function renderTools(tools) {
    const grid = el("tool-grid");
    if (!tools || tools.length === 0) {
        grid.innerHTML = '<p class="empty-state">No tools configured.</p>';
        return;
    }

    grid.innerHTML = tools.map(t => {
        const badgeCls  = t.online ? "online" : "offline";
        const badgeText = t.online ? "Online" : "Offline";
        const launchDisabled = t.online ? "" : "disabled";
        const errorHint = (!t.online && t.error)
            ? `<span title="${escapeHtml(t.error)}" style="cursor:help">&#x26A0;&#xFE0F;</span>`
            : "";

        return `
        <div class="tool-card" id="card-${escapeHtml(t.key)}">
            <div class="tool-card-header">
                <span class="tool-label">${escapeHtml(t.label)}</span>
                <span class="tool-badge ${badgeCls}">
                    <span class="dot"></span>${badgeText}${errorHint}
                </span>
            </div>
            <div class="tool-description">${escapeHtml(t.description)}</div>
            <div class="tool-category">${escapeHtml(t.category)}</div>
            <div class="tool-card-footer">
                <a href="${escapeHtml(t.url)}" target="_blank" rel="noopener"
                   class="btn btn-primary" ${launchDisabled}>Launch</a>
            </div>
        </div>`;
    }).join("");
}

// ---------------------------------------------------------------------------
// ir-chain pipeline panel
// ---------------------------------------------------------------------------

async function fetchIrChain() {
    try {
        const resp = await fetch("/api/pipeline/ir-chain");
        const data = await resp.json();
        renderIrChain(data);
    } catch (err) {
        console.error("ir-chain fetch failed:", err);
    }
}

function renderIrChain(data) {
    const panel = el("irchain-panel");

    const pendingCls  = data.pending_cases  > 0 ? "pending" : "zero";
    const processedCls = data.processed_cases > 0 ? "" : "zero";

    let pathWarnings = "";
    if (!data.triage_path_ok) {
        pathWarnings += `<div class="path-warning">&#9888; Triage output path not found — check config.yaml</div>`;
    }
    if (!data.reports_path_ok) {
        pathWarnings += `<div class="path-warning">&#9888; SIREN reports path not found — no cases processed yet</div>`;
    }

    let reportsHtml = "";
    if (!data.recent_reports || data.recent_reports.length === 0) {
        reportsHtml = '<div class="empty-state">No reports yet.</div>';
    } else {
        reportsHtml = `<ul class="run-list">` +
            data.recent_reports.map(r => {
                const sev = (r.severity || "").toLowerCase();
                const sevBadge = sev
                    ? `<span class="severity-badge ${sev}">${escapeHtml(r.severity)}</span>`
                    : "";
                return `
                <li class="run-item">
                    <span class="run-name" title="${escapeHtml(r.title)}">${escapeHtml(r.title)}</span>
                    ${sevBadge}
                    <span class="run-detail">${timeAgo(r.modified)}</span>
                </li>`;
            }).join("") +
            `</ul>`;
    }

    panel.innerHTML = `
        <div class="pipeline-meta">
            <div class="meta-item">
                <span class="meta-value">${data.total_cases}</span>
                <span class="meta-label">Total cases</span>
            </div>
            <div class="meta-item">
                <span class="meta-value ${processedCls}">${data.processed_cases}</span>
                <span class="meta-label">Processed</span>
            </div>
            <div class="meta-item">
                <span class="meta-value ${pendingCls}">${data.pending_cases}</span>
                <span class="meta-label">Pending</span>
            </div>
        </div>
        <div class="pipeline-body">
            ${pathWarnings}
            ${reportsHtml}
        </div>
    `;
}

// ---------------------------------------------------------------------------
// detection-pipeline panel
// ---------------------------------------------------------------------------

async function fetchDetectionPipeline() {
    try {
        const resp = await fetch("/api/pipeline/detection-pipeline");
        const data = await resp.json();
        renderDetectionPipeline(data);
    } catch (err) {
        console.error("detection-pipeline fetch failed:", err);
    }
}

function renderDetectionPipeline(data) {
    const panel = el("detection-panel");

    let pathWarning = "";
    if (!data.output_path_ok) {
        pathWarning = `<div class="path-warning">&#9888; Output path not found — no runs yet</div>`;
    }

    let runsHtml = "";
    if (!data.recent_runs || data.recent_runs.length === 0) {
        runsHtml = '<div class="empty-state">No runs yet.</div>';
    } else {
        runsHtml = `<ul class="run-list">` +
            data.recent_runs.map(r => {
                const gen = r.rules_generated || {};
                const genTotal = Object.values(gen).reduce((a, b) => a + b, 0);
                const failed = r.rules_failed || {};
                const failTotal = Object.values(failed).reduce((a, b) => a + b, 0);
                const failBit = failTotal > 0
                    ? ` <span style="color:var(--accent-red)">${failTotal} failed</span>`
                    : "";
                const detail = r.processed !== undefined
                    ? `${r.processed} IOCs &bull; ${genTotal} rules${failBit}`
                    : "";
                return `
                <li class="run-item">
                    <span class="run-name" title="${escapeHtml(r.run)}">${escapeHtml(r.run)}</span>
                    <span class="run-detail">${detail}</span>
                    <span class="run-detail">${timeAgo(r.modified)}</span>
                </li>`;
            }).join("") +
            `</ul>`;
    }

    panel.innerHTML = `
        <div class="pipeline-body">
            ${pathWarning}
            ${runsHtml}
        </div>
    `;
}

// ---------------------------------------------------------------------------
// Incident reports
// ---------------------------------------------------------------------------

async function fetchReports() {
    try {
        const resp = await fetch("/api/reports");
        const data = await resp.json();
        renderReportList(data);
    } catch (err) {
        console.error("Reports fetch failed:", err);
    }
}

function renderReportList(reports) {
    const section = el("reports-section");
    if (!reports || reports.length === 0) {
        section.innerHTML = '<div class="empty-state">No incident reports yet.</div>';
        return;
    }

    section.innerHTML = `
        <div class="report-list">
            ${reports.map((r, i) => {
                const sev = (r.severity || "").toLowerCase();
                const sevBadge = sev
                    ? `<span class="severity-badge ${sev}">${escapeHtml(r.severity)}</span>`
                    : "";
                const iocCount  = (r.iocs  || []).length;
                const sysCount  = (r.affected_systems || []).length;
                const tlCount   = (r.timeline || []).length;
                return `
                <div class="report-list-item" role="button" tabindex="0"
                     data-report-index="${i}" title="Click to view full report">
                    <div class="rli-left">
                        <span class="rli-id">${escapeHtml(r.incident_id || "—")}</span>
                        <span class="rli-title">${escapeHtml(r.title || r._file)}</span>
                    </div>
                    <div class="rli-right">
                        ${sevBadge}
                        <span class="rli-meta">${escapeHtml(r.category || "")}</span>
                        <span class="rli-meta">${iocCount} IOC${iocCount !== 1 ? "s" : ""}</span>
                        <span class="rli-meta">${sysCount} system${sysCount !== 1 ? "s" : ""}</span>
                        <span class="rli-meta rli-time">${timeAgo(r._modified)}</span>
                        <span class="rli-arrow">&#8250;</span>
                    </div>
                </div>`;
            }).join("")}
        </div>`;

    // Store reports data for click handler
    section._reports = reports;

    section.querySelectorAll(".report-list-item").forEach(item => {
        const open = () => {
            const idx = parseInt(item.dataset.reportIndex, 10);
            openReport(section._reports[idx]);
        };
        item.addEventListener("click", open);
        item.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") open(); });
    });
}

function openReport(r) {
    el("report-modal-id").textContent    = r.incident_id || "";
    el("report-modal-title").textContent = r.title || r._file || "Untitled";

    const dates  = r.dates  || {};
    const score  = r.severity_score || {};
    const tl     = r.timeline || [];
    const iocs   = r.iocs || [];
    const systems = r.affected_systems || [];
    const recs   = r.recommendations || [];

    const dateRow = [
        ["Detection",    dates.detection],
        ["Containment",  dates.containment],
        ["Eradication",  dates.eradication],
        ["Recovery",     dates.recovery],
    ].filter(([, v]) => v).map(([label, val]) => `
        <div class="rd-date-item">
            <span class="rd-date-label">${escapeHtml(label)}</span>
            <span class="rd-date-value">${escapeHtml(val)}</span>
        </div>`).join("");

    const tlRows = tl.map((e, i) => `
        <tr>
            <td class="rd-td-num">${i + 1}</td>
            <td class="rd-td-mono">${escapeHtml(e.timestamp || "")}</td>
            <td>${escapeHtml(e.description || "")}</td>
            <td class="rd-td-muted">${escapeHtml(e.source || "—")}</td>
        </tr>`).join("");

    const iocRows = iocs.map((ioc, i) => `
        <tr>
            <td class="rd-td-num">${i + 1}</td>
            <td class="rd-td-muted">${escapeHtml(ioc.ioc_type || "")}</td>
            <td class="rd-td-mono">${escapeHtml(ioc.value || "")}</td>
            <td class="rd-td-muted">${escapeHtml(ioc.context || "—")}</td>
        </tr>`).join("");

    const sysRows = systems.map((s, i) => `
        <tr>
            <td class="rd-td-num">${i + 1}</td>
            <td class="rd-td-mono">${escapeHtml(s.hostname || "")}</td>
            <td class="rd-td-mono">${escapeHtml(s.ip_address || "")}</td>
            <td class="rd-td-muted">${escapeHtml(s.impact || "—")}</td>
        </tr>`).join("");

    const sev = (r.severity || "").toLowerCase();
    const sevBadge = sev
        ? `<span class="severity-badge ${sev}">${escapeHtml(r.severity)}</span>`
        : "";

    el("report-modal-body").innerHTML = `
        <div class="rd-meta-grid">
            <div class="rd-meta-item"><span class="rd-meta-label">Severity</span>
                <span>${sevBadge}</span></div>
            <div class="rd-meta-item"><span class="rd-meta-label">Category</span>
                <span class="rd-meta-value">${escapeHtml(r.category || "—")}</span></div>
            <div class="rd-meta-item"><span class="rd-meta-label">Analyst</span>
                <span class="rd-meta-value">${escapeHtml(r.analyst || "—")}</span></div>
            <div class="rd-meta-item"><span class="rd-meta-label">Score</span>
                <span class="rd-meta-value">${score.score != null ? score.score + "/10 (" + escapeHtml(score.rating || "") + ")" : "—"}</span></div>
            <div class="rd-meta-item"><span class="rd-meta-label">Created</span>
                <span class="rd-meta-value">${escapeHtml(r.created_at || "—")}</span></div>
        </div>

        ${dateRow ? `<div class="rd-dates">${dateRow}</div>` : ""}

        ${r.description ? `
        <div class="rd-section">
            <div class="rd-section-title">Description</div>
            <div class="rd-text">${escapeHtml(r.description)}</div>
        </div>` : ""}

        ${r.executive_summary ? `
        <div class="rd-section">
            <div class="rd-section-title">Executive Summary</div>
            <div class="rd-text">${escapeHtml(r.executive_summary)}</div>
        </div>` : ""}

        ${tl.length ? `
        <div class="rd-section">
            <div class="rd-section-title">Timeline <span class="rd-count">${tl.length}</span></div>
            <table class="rd-table">
                <thead><tr><th>#</th><th>Timestamp</th><th>Event</th><th>Source</th></tr></thead>
                <tbody>${tlRows}</tbody>
            </table>
        </div>` : ""}

        ${iocs.length ? `
        <div class="rd-section">
            <div class="rd-section-title">Indicators of Compromise <span class="rd-count">${iocs.length}</span></div>
            <table class="rd-table">
                <thead><tr><th>#</th><th>Type</th><th>Value</th><th>Context</th></tr></thead>
                <tbody>${iocRows}</tbody>
            </table>
        </div>` : ""}

        ${systems.length ? `
        <div class="rd-section">
            <div class="rd-section-title">Affected Systems <span class="rd-count">${systems.length}</span></div>
            <table class="rd-table">
                <thead><tr><th>#</th><th>Hostname</th><th>IP</th><th>Impact</th></tr></thead>
                <tbody>${sysRows}</tbody>
            </table>
        </div>` : ""}

        ${recs.length ? `
        <div class="rd-section">
            <div class="rd-section-title">Recommendations <span class="rd-count">${recs.length}</span></div>
            <ol class="rd-recs">${recs.map(rec => `<li>${escapeHtml(rec)}</li>`).join("")}</ol>
        </div>` : ""}
    `;

    const overlay = el("report-modal-overlay");
    overlay.style.display = "flex";
    overlay.scrollTop = 0;
    el("report-modal-body").scrollTop = 0;
    el("report-modal-close").focus();
}

function closeReport() {
    el("report-modal-overlay").style.display = "none";
}

// ---------------------------------------------------------------------------
// Auto-refresh
// ---------------------------------------------------------------------------

let refreshTimer    = null;
let countdownTimer  = null;
let nextRefreshAt   = null;

function startCountdown() {
    clearInterval(countdownTimer);
    nextRefreshAt = Date.now() + REFRESH_INTERVAL_MS;
    countdownTimer = setInterval(() => {
        const secs = Math.max(0, Math.round((nextRefreshAt - Date.now()) / 1000));
        el("last-updated").textContent = `Refreshing in ${secs}s`;
    }, 1000);
}

function stopCountdown() {
    clearInterval(countdownTimer);
    el("last-updated").textContent = "Refreshing\u2026";
}

function scheduleRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => {
        refresh();
    }, REFRESH_INTERVAL_MS);
    startCountdown();
}

async function refresh() {
    stopCountdown();
    await Promise.all([
        fetchStatus(),
        fetchIrChain(),
        fetchDetectionPipeline(),
        fetchReports(),
    ]);
    scheduleRefresh();
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
    el("refresh-btn").addEventListener("click", () => {
        clearTimeout(refreshTimer);
        clearInterval(countdownTimer);
        refresh();
    });

    // Modal close handlers
    el("report-modal-close").addEventListener("click", closeReport);
    el("report-modal-overlay").addEventListener("click", e => {
        if (e.target === el("report-modal-overlay")) closeReport();
    });
    document.addEventListener("keydown", e => {
        if (e.key === "Escape") closeReport();
    });

    refresh();
});
