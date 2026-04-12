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
// Auto-refresh
// ---------------------------------------------------------------------------

let refreshTimer = null;

function scheduleRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => {
        refresh();
    }, REFRESH_INTERVAL_MS);
}

async function refresh() {
    await Promise.all([
        fetchStatus(),
        fetchIrChain(),
        fetchDetectionPipeline(),
    ]);
    scheduleRefresh();
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
    el("refresh-btn").addEventListener("click", () => {
        clearTimeout(refreshTimer);
        refresh();
    });

    refresh();
});
