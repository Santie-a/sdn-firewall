/* SDN Firewall Controller — app.js
   6a: tab switching, form clear, basic validation.
   6b: flow table rendering, toggle, delete.
   6c–6e will add nodes, events, and full server sync. */

// When served by FastAPI (/ui), use the same origin.
// When opened as a local file, fall back to localhost:5000.
const SERVER = window.location.protocol === "file:"
  ? "http://localhost:5000"
  : window.location.origin;

// -------------------------------------------------------------------------
// Tab switching
// -------------------------------------------------------------------------
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
  });
});

// -------------------------------------------------------------------------
// Form — clear
// -------------------------------------------------------------------------
document.getElementById("clearBtn").addEventListener("click", clearForm);

function clearForm() {
  document.getElementById("fName").value      = "";
  document.getElementById("fPriority").value  = "";
  document.getElementById("fSrcIp").value     = "";
  document.getElementById("fDstIp").value     = "";
  document.getElementById("fProto").value     = "";
  document.getElementById("fSrcPort").value   = "";
  document.getElementById("fDstPort").value   = "";
  document.getElementById("fInPort").value    = "";
  document.getElementById("fEthType").value   = "";
  document.getElementById("fSrcMac").value    = "";
  document.getElementById("fDstMac").value    = "";
  document.getElementById("fVlanId").value    = "";
  document.getElementById("fVlanPri").value   = "";
  document.getElementById("fTos").value       = "";
  document.getElementById("fEnabled").checked = true;
  document.querySelector('input[name="action"][value="allow"]').checked = true;
  document.querySelectorAll("input.invalid").forEach(el => el.classList.remove("invalid"));
  hideError();
}

// -------------------------------------------------------------------------
// Form — validation helpers
// -------------------------------------------------------------------------
function showError(msg) {
  const el = document.getElementById("formError");
  el.textContent = msg;
  el.classList.remove("hidden");
}

function hideError() {
  document.getElementById("formError").classList.add("hidden");
}

function readOptionalInt(id) {
  const v = document.getElementById(id).value.trim();
  if (v === "") return null;
  const n = parseInt(v, 10);
  return isNaN(n) ? null : n;
}

function readOptionalStr(id) {
  const v = document.getElementById(id).value.trim();
  return v === "" ? null : v;
}

// -------------------------------------------------------------------------
// Form — build rule payload
// -------------------------------------------------------------------------
function buildPayload() {
  const name     = document.getElementById("fName").value.trim();
  const priority = parseInt(document.getElementById("fPriority").value, 10);
  const action   = document.querySelector('input[name="action"]:checked').value;
  const enabled  = document.getElementById("fEnabled").checked;

  // Required field validation
  let valid = true;
  if (!name) {
    document.getElementById("fName").classList.add("invalid");
    valid = false;
  } else {
    document.getElementById("fName").classList.remove("invalid");
  }
  if (isNaN(priority) || priority < 0 || priority > 65535) {
    document.getElementById("fPriority").classList.add("invalid");
    valid = false;
  } else {
    document.getElementById("fPriority").classList.remove("invalid");
  }
  if (!valid) {
    showError("Please fill in all required fields correctly.");
    return null;
  }

  hideError();
  return {
    name, priority, action, enabled,
    match: {
      src_ip:        readOptionalStr("fSrcIp"),
      dst_ip:        readOptionalStr("fDstIp"),
      protocol:      readOptionalStr("fProto"),
      src_port:      readOptionalInt("fSrcPort"),
      dst_port:      readOptionalInt("fDstPort"),
      in_port:       readOptionalStr("fInPort"),
      eth_type:      readOptionalStr("fEthType"),
      src_mac:       readOptionalStr("fSrcMac"),
      dst_mac:       readOptionalStr("fDstMac"),
      vlan_id:       readOptionalInt("fVlanId"),
      vlan_priority: readOptionalInt("fVlanPri"),
      tos:           readOptionalStr("fTos"),
    }
  };
}

// -------------------------------------------------------------------------
// Form — submit (wired to server in 6e; stub for now)
// -------------------------------------------------------------------------
document.getElementById("ruleForm").addEventListener("submit", async e => {
  e.preventDefault();
  const payload = buildPayload();
  if (!payload) return;

  const btn = document.getElementById("submitBtn");
  btn.disabled = true;
  btn.textContent = "Adding…";
  try {
    await submitRule(payload);
    clearForm();
  } catch (err) {
    showError(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Add Rule";
  }
});

// -------------------------------------------------------------------------
// Server helpers
// -------------------------------------------------------------------------
async function api(method, path, body) {
  const res = await fetch(`${SERVER}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || `HTTP ${res.status}`);
  }
  return res.status === 204 ? null : res.json();
}

// -------------------------------------------------------------------------
// Rule submit — posts to server, refreshes table
// -------------------------------------------------------------------------
async function submitRule(payload) {
  await api("POST", "/rules", payload);
  await loadRules();
}

// -------------------------------------------------------------------------
// 6b — Flow table
// -------------------------------------------------------------------------
const WILDCARD = "<span class='wc'>*</span>";

function fmt(v) {
  return (v === null || v === undefined || v === "") ? WILDCARD : v;
}

function actionTag(action) {
  return `<span class="tag tag--${action}">${action}</span>`;
}

function renderRules(rules) {
  const tbody = document.getElementById("flowTableBody");
  document.getElementById("ruleCount").textContent =
    `${rules.length} rule${rules.length !== 1 ? "s" : ""}`;

  if (rules.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="12">No rules yet. Add one using the form.</td></tr>`;
    return;
  }

  tbody.innerHTML = rules.map(r => {
    const m = r.match;
    const disabled = r.enabled ? "" : "disabled";
    return `
      <tr class="${r.enabled ? "" : "disabled"}" data-id="${r.id}">
        <td><strong>${r.priority}</strong></td>
        <td>${r.name}</td>
        <td>${fmt(m.src_ip)}</td>
        <td>${fmt(m.dst_ip)}</td>
        <td>${fmt(m.protocol)}</td>
        <td>${fmt(m.src_port)}</td>
        <td>${fmt(m.dst_port)}</td>
        <td>${actionTag(r.action)}</td>
        <td>${r.stats.packet_count.toLocaleString()}</td>
        <td>${formatBytes(r.stats.byte_count)}</td>
        <td><span class="tag tag--${r.enabled ? "active" : "inactive"}">${r.enabled ? "On" : "Off"}</span></td>
        <td class="row-actions">
          <button class="icon-btn toggle-btn" title="${r.enabled ? "Disable" : "Enable"}" data-id="${r.id}">
            ${r.enabled ? "⏸" : "▶"}
          </button>
          <button class="icon-btn delete delete-btn" title="Delete" data-id="${r.id}">🗑</button>
        </td>
      </tr>`;
  }).join("");

  // Toggle
  tbody.querySelectorAll(".toggle-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        await api("PATCH", `/rules/${btn.dataset.id}/toggle`);
        await loadRules();
      } catch (e) {
        console.error(e);
      }
    });
  });

  // Delete
  tbody.querySelectorAll(".delete-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      if (!confirm("Delete this rule?")) return;
      btn.disabled = true;
      try {
        await api("DELETE", `/rules/${btn.dataset.id}`);
        await loadRules();
      } catch (e) {
        console.error(e);
      }
    });
  });
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

async function loadRules() {
  try {
    const rules = await api("GET", "/rules");
    renderRules(rules);
    setStatus(true);
  } catch {
    setStatus(false);
  }
}

// -------------------------------------------------------------------------
// Server status indicator
// -------------------------------------------------------------------------
function setStatus(ok) {
  const dot   = document.getElementById("statusDot");
  const label = document.getElementById("statusLabel");
  dot.className     = `status-dot ${ok ? "ok" : "error"}`;
  label.textContent = ok ? "Controller online" : "Controller unreachable";
}

// -------------------------------------------------------------------------
// 6c — Nodes panel
// -------------------------------------------------------------------------
function formatTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleDateString([], { month: "short", day: "numeric" })
    + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function staleness(iso) {
  if (!iso) return Infinity;
  return (Date.now() - new Date(iso).getTime()) / 1000;
}

function renderNodes(nodes) {
  const tbody = document.getElementById("nodeTableBody");
  document.getElementById("nodeCount").textContent =
    `${nodes.length} node${nodes.length !== 1 ? "s" : ""}`;

  if (nodes.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="6">No nodes registered yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = nodes.map(n => {
    // Mark stale if last heartbeat > 3× poll interval (assume 30 s default)
    const stale  = staleness(n.last_seen) > 30;
    const status = stale ? "inactive" : n.status;
    return `
      <tr>
        <td><code>${n.node_id}</code></td>
        <td>${n.ip}</td>
        <td>${n.listen_port}</td>
        <td><span class="tag tag--${status}">${status}</span></td>
        <td>${formatDate(n.registered_at)}</td>
        <td class="${stale ? "stale-time" : ""}">${formatTime(n.last_seen)}</td>
      </tr>`;
  }).join("");
}

async function loadNodes() {
  try {
    const nodes = await api("GET", "/nodes");
    renderNodes(nodes);
  } catch {
    // status dot already handled by loadRules
  }
}

// -------------------------------------------------------------------------
// 6d — Event log
// -------------------------------------------------------------------------
let _events = [];

function renderEvents(events) {
  const filter = document.getElementById("filterAction").value;
  const tbody  = document.getElementById("eventTableBody");
  const rows   = filter ? events.filter(e => e.action === filter) : events;

  if (rows.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="10">No events yet.</td></tr>`;
    return;
  }

  // Show newest first
  tbody.innerHTML = [...rows].reverse().map(e => {
    const p = e.packet;
    return `
      <tr class="event-row event-row--${e.action}">
        <td class="mono">${formatTime(e.timestamp)}</td>
        <td><code>${e.node_id}</code></td>
        <td>${actionTag({ allowed: "allow", blocked: "block", reported: "report" }[e.action] || e.action)}</td>
        <td>${fmt(p.src_ip)}</td>
        <td>${fmt(p.dst_ip)}</td>
        <td>${fmt(p.protocol)}</td>
        <td>${fmt(p.src_port)}</td>
        <td>${fmt(p.dst_port)}</td>
        <td>${formatBytes(p.size)}</td>
        <td class="mono muted">${e.rule_id ? e.rule_id.slice(0, 8) + "…" : "default"}</td>
      </tr>`;
  }).join("");
}

async function loadEvents() {
  try {
    _events = await api("GET", "/events?limit=200");
    renderEvents(_events);
  } catch {
    // status dot handled by loadRules
  }
}

// Re-render on filter change (no extra fetch needed)
document.getElementById("filterAction").addEventListener("change", () => renderEvents(_events));

// Clear event log
document.getElementById("clearEventsBtn").addEventListener("click", async () => {
  if (!confirm("Clear all events?")) return;
  try {
    await api("DELETE", "/events");
    _events = [];
    renderEvents(_events);
  } catch (e) {
    console.error(e);
  }
});

// -------------------------------------------------------------------------
// Last-updated indicator
// -------------------------------------------------------------------------
function touchUpdated() {
  const el = document.getElementById("lastUpdated");
  if (el) el.textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

async function pollAll() {
  await Promise.allSettled([loadRules(), loadNodes(), loadEvents()]);
  touchUpdated();
}

// -------------------------------------------------------------------------
// Boot: initial load + polling (5 s)
// -------------------------------------------------------------------------
pollAll();
setInterval(pollAll, 5000);
