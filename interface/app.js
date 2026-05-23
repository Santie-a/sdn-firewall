/* SDN Firewall Controller — app.js */

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
// Form — submit
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
// Scenario presets — bulk-load common rule sets (covers spec test scenarios)
// -------------------------------------------------------------------------
const EMPTY_MATCH = {
  src_ip: null, dst_ip: null, protocol: null, src_port: null, dst_port: null,
  in_port: null, src_mac: null, dst_mac: null, eth_type: null,
  vlan_id: null, vlan_priority: null, tos: null,
};

function mkRule(name, action, priority, match) {
  return { name, action, priority, enabled: true, match: { ...EMPTY_MATCH, ...match } };
}

const PRESETS = {
  web: {
    name: "Allow Web Traffic",
    rules: [
      mkRule("Allow HTTP",  "allow", 100, { protocol: "TCP", dst_port: 80  }),
      mkRule("Allow HTTPS", "allow", 100, { protocol: "TCP", dst_port: 443 }),
      mkRule("Allow DNS",   "allow", 100, { protocol: "UDP", dst_port: 53  }),
    ],
  },
  lockdown: {
    name: "Lock Sensitive Ports",
    rules: [
      mkRule("Block SSH",    "block", 200, { protocol: "TCP", dst_port: 22   }),
      mkRule("Block Telnet", "block", 200, { protocol: "TCP", dst_port: 23   }),
      mkRule("Block RDP",    "block", 200, { protocol: "TCP", dst_port: 3389 }),
    ],
  },
  udp: {
    name: "UDP Test Set",
    rules: [
      mkRule("Allow UDP 9000",  "allow",  100, { protocol: "UDP", dst_port: 9000 }),
      mkRule("Block UDP 9001",  "block",  100, { protocol: "UDP", dst_port: 9001 }),
      mkRule("Report UDP 9002", "report", 100, { protocol: "UDP", dst_port: 9002 }),
    ],
  },
  audit: {
    name: "Audit Mode",
    rules: [
      mkRule("Report all traffic", "report", 1, {}),
    ],
  },
  conflict: {
    name: "Priority Conflict",
    rules: [
      mkRule("HIGH PRI: Block UDP 9000", "block", 300, { protocol: "UDP", dst_port: 9000 }),
      mkRule("LOW PRI: Allow UDP 9000",  "allow", 100, { protocol: "UDP", dst_port: 9000 }),
    ],
  },
};

async function applyPreset(key, btn) {
  const preset = PRESETS[key];
  if (!preset) return;
  if (!confirm(`Add ${preset.rules.length} rule(s) from "${preset.name}"?`)) return;
  btn.disabled = true;
  try {
    for (const rule of preset.rules) {
      await api("POST", "/rules", rule);
    }
    await loadRules();
  } catch (e) {
    alert("Failed to apply preset: " + e.message);
  } finally {
    btn.disabled = false;
  }
}

async function clearAllRules(btn) {
  if (_rules.length === 0) {
    alert("No rules to clear.");
    return;
  }
  if (!confirm(`Delete ALL ${_rules.length} rule(s)? This cannot be undone.`)) return;
  btn.disabled = true;
  try {
    for (const r of [..._rules]) {
      await api("DELETE", `/rules/${r.id}`);
    }
    await loadRules();
  } catch (e) {
    alert("Failed to clear: " + e.message);
  } finally {
    btn.disabled = false;
  }
}

// Wire up buttons
document.querySelectorAll(".preset-btn[data-preset]").forEach(btn => {
  btn.addEventListener("click", () => applyPreset(btn.dataset.preset, btn));
});
document.getElementById("clearAllBtn").addEventListener("click", e => clearAllRules(e.currentTarget));

// -------------------------------------------------------------------------
// HTML escape helper — use for any user-controlled string injected via innerHTML
// -------------------------------------------------------------------------
function esc(v) {
  if (v === null || v === undefined) return "";
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// -------------------------------------------------------------------------
// Rule interpreter — converts a rule object into a natural-language sentence
// -------------------------------------------------------------------------
function interpretRule(rule) {
  const m = rule.match;
  const verbs    = { allow: "Allow", block: "Block", report: "Report" };
  const verbPast = { allow: "allowed", block: "blocked", report: "reported" };
  const verb = verbs[rule.action] || rule.action;

  const clauses = [];
  if (m.src_ip)     clauses.push(`from <b>${esc(m.src_ip)}</b>`);
  if (m.src_port)   clauses.push(`from port <b>${esc(m.src_port)}</b>`);
  if (m.dst_ip)     clauses.push(`to <b>${esc(m.dst_ip)}</b>`);
  if (m.dst_port)   clauses.push(`to port <b>${esc(m.dst_port)}</b>`);
  if (m.src_mac)    clauses.push(`from MAC <b>${esc(m.src_mac)}</b>`);
  if (m.dst_mac)    clauses.push(`to MAC <b>${esc(m.dst_mac)}</b>`);
  if (m.in_port)    clauses.push(`via <b>${esc(m.in_port)}</b>`);
  if (m.eth_type)   clauses.push(`of type <b>${esc(m.eth_type)}</b>`);
  if (m.vlan_id != null)       clauses.push(`in VLAN <b>${esc(m.vlan_id)}</b>`);
  if (m.vlan_priority != null) clauses.push(`VLAN priority <b>${esc(m.vlan_priority)}</b>`);
  if (m.tos)        clauses.push(`with ToS <b>${esc(m.tos)}</b>`);

  const subject = m.protocol
    ? `<b>${esc(m.protocol)}</b> traffic`
    : (clauses.length ? "traffic" : "all traffic");

  const matchPart = clauses.length ? " " + clauses.join(" ") : "";
  const enabledNote = rule.enabled ? "" : " <i>(disabled)</i>";

  return `${verb} ${subject}${matchPart}. Priority <b>${esc(rule.priority)}</b>.${enabledNote}`;
}

// -------------------------------------------------------------------------
// Flow table
// -------------------------------------------------------------------------
const WILDCARD = "<span class='wc'>*</span>";

function fmt(v) {
  return (v === null || v === undefined || v === "") ? WILDCARD : esc(v);
}

function actionTag(action) {
  return `<span class="tag tag--${esc(action)}">${esc(action)}</span>`;
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
    return `
      <tr class="${r.enabled ? "" : "disabled"}" data-id="${esc(r.id)}">
        <td><strong>${esc(r.priority)}</strong></td>
        <td>
          <div class="rule-name">${esc(r.name)}</div>
          <div class="rule-interp">${interpretRule(r)}</div>
        </td>
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
          <button class="icon-btn toggle-btn" title="${r.enabled ? "Disable" : "Enable"}" data-id="${esc(r.id)}">
            ${r.enabled ? "⏸" : "▶"}
          </button>
          <button class="icon-btn delete delete-btn" title="Delete" data-id="${esc(r.id)}">🗑</button>
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

let _rules = [];
let _nodes = [];

async function loadRules() {
  _rules = await api("GET", "/rules");
  renderRules(_rules);
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
// Nodes panel
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
    tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No nodes registered yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = nodes.map(n => {
    // Revoked is a sticky admin state — stale logic doesn't apply to it.
    // For non-revoked nodes, also flag any row older than the threshold locally.
    const revoked = n.status === "revoked";
    const stale   = !revoked && staleness(n.last_seen) > 10;
    const status  = revoked ? "revoked" : (stale ? "inactive" : n.status);

    // Per status, the trash icon means different things. Build the actions cell.
    let actions;
    if (revoked) {
      actions = `
        <button class="icon-btn admit-btn"  title="Admit this node back into the fabric" data-id="${esc(n.node_id)}">✓</button>
        <button class="icon-btn delete forget-btn" title="Forget this node entirely (allows rejoin)" data-id="${esc(n.node_id)}">🗑</button>
      `;
    } else if (status === "active") {
      actions = `
        <button class="icon-btn delete revoke-btn" title="Revoke — eject and block from rejoining" data-id="${esc(n.node_id)}">⛔</button>
      `;
    } else {
      actions = `
        <button class="icon-btn delete forget-btn" title="Forget this node (it may rejoin if it comes back)" data-id="${esc(n.node_id)}">🗑</button>
      `;
    }

    // Time column shows revoked_at for revoked rows, last_seen otherwise.
    const timeCell = revoked
      ? `<span title="Revoked">⛔ ${formatTime(n.revoked_at)}</span>`
      : `<span class="${stale ? "stale-time" : ""}">${formatTime(n.last_seen)}</span>`;

    return `
      <tr class="${revoked ? "revoked" : ""}">
        <td><code>${esc(n.node_id)}</code></td>
        <td>${esc(n.ip)}</td>
        <td>${esc(n.listen_port)}</td>
        <td><span class="tag tag--${esc(status)}">${esc(status)}</span></td>
        <td>${formatDate(n.registered_at)}</td>
        <td>${timeCell}</td>
        <td class="row-actions">${actions}</td>
      </tr>`;
  }).join("");

  tbody.querySelectorAll(".revoke-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      if (!confirm(`Revoke node "${id}"?\n\nIt will be ejected from the fabric and blocked from rejoining until you admit it.`)) return;
      btn.disabled = true;
      try {
        await api("POST", `/nodes/${encodeURIComponent(id)}/revoke`);
        await loadNodes();
      } catch (e) {
        alert("Failed: " + e.message);
      }
    });
  });

  tbody.querySelectorAll(".admit-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      if (!confirm(`Admit node "${id}" back? It will be allowed to rejoin on its next registration.`)) return;
      btn.disabled = true;
      try {
        await api("POST", `/nodes/${encodeURIComponent(id)}/admit`);
        await loadNodes();
      } catch (e) {
        alert("Failed: " + e.message);
      }
    });
  });

  tbody.querySelectorAll(".forget-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      if (!confirm(`Forget node "${id}"?\n\nThe record will be deleted. If the node is still running, it may re-register and reappear.`)) return;
      btn.disabled = true;
      try {
        await api("DELETE", `/nodes/${encodeURIComponent(id)}`);
        await loadNodes();
      } catch (e) {
        alert("Failed: " + e.message);
      }
    });
  });
}

async function loadNodes() {
  _nodes = await api("GET", "/nodes");
  renderNodes(_nodes);
}

document.getElementById("clearInactiveBtn").addEventListener("click", async (e) => {
  // Revoked nodes are tombstones — not "inactive" in the cleanup sense.
  const inactiveCount = _nodes.filter(n =>
    n.status !== "revoked" && (n.status === "inactive" || staleness(n.last_seen) > 10)
  ).length;
  if (inactiveCount === 0) {
    alert("No inactive nodes to clear.");
    return;
  }
  if (!confirm(`Remove ${inactiveCount} inactive node(s) from the registry?`)) return;
  const btn = e.currentTarget;
  btn.disabled = true;
  try {
    await api("DELETE", "/nodes?status=inactive");
    await loadNodes();
  } catch (err) {
    alert("Failed: " + err.message);
  } finally {
    btn.disabled = false;
  }
});

// -------------------------------------------------------------------------
// Event log
// -------------------------------------------------------------------------
let _events = [];

function renderEvents(events) {
  const filter = document.getElementById("filterAction").value;
  const tbody  = document.getElementById("eventTableBody");
  const rows   = filter ? events.filter(e => e.action === filter) : events;

  if (rows.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="11">No events yet.</td></tr>`;
    return;
  }

  // Show newest first
  tbody.innerHTML = [...rows].reverse().map(e => {
    const p = e.packet;
    return `
      <tr class="event-row event-row--${esc(e.action)}">
        <td class="mono">${formatTime(e.timestamp)}</td>
        <td><code>${esc(e.node_id)}</code></td>
        <td>${actionTag({ allowed: "allow", blocked: "block", reported: "report" }[e.action] || e.action)}</td>
        <td>${fmt(p.src_ip)}</td>
        <td>${fmt(p.dst_ip)}</td>
        <td>${fmt(p.protocol)}</td>
        <td>${fmt(p.src_port)}</td>
        <td>${fmt(p.dst_port)}</td>
        <td>${formatBytes(p.size)}</td>
        <td class="event-msg">${esc(p.message || "")}</td>
        <td class="mono muted">${e.rule_id ? esc(e.rule_id.slice(0, 8)) + "…" : "default"}</td>
      </tr>`;
  }).join("");
}

async function loadEvents() {
  _events = await api("GET", "/events?limit=200");
  renderEvents(_events);
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
  const results = await Promise.allSettled([loadRules(), loadNodes(), loadEvents()]);
  setStatus(results.every(r => r.status === "fulfilled"));
  updateDashboard();
  renderTopology();
  pulseNewEvents();
  touchUpdated();
}

// -------------------------------------------------------------------------
// Topology graph (SVG, radial layout)
// -------------------------------------------------------------------------
const TOPO_W      = 600;
const TOPO_H      = 420;
const TOPO_CX     = TOPO_W / 2;
const TOPO_CY     = TOPO_H / 2;
const TOPO_RADIUS = 150;

const SVG_NS = "http://www.w3.org/2000/svg";

function svgEl(name, attrs = {}, text = null) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (text !== null) el.textContent = text;
  return el;
}

function nodePosition(i, n) {
  // Start at top (-π/2), distribute around the circle
  const angle = (2 * Math.PI * i) / n - Math.PI / 2;
  return {
    x: TOPO_CX + TOPO_RADIUS * Math.cos(angle),
    y: TOPO_CY + TOPO_RADIUS * Math.sin(angle),
  };
}

// Keep node positions so pulses can find them between renders
const _topoPositions = {};

function renderTopology() {
  const svg   = document.getElementById("topology");
  const empty = document.getElementById("topoEmpty");
  if (!svg) return;

  // Wipe and redraw
  svg.innerHTML = "";

  // Revoked nodes are not part of the fabric — hide them from the graph.
  const fabricNodes = _nodes.filter(n => n.status !== "revoked");

  if (fabricNodes.length === 0) {
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");

  // Links first, so they render under nodes
  fabricNodes.forEach((_, i) => {
    const { x, y } = nodePosition(i, fabricNodes.length);
    svg.appendChild(svgEl("line", {
      x1: TOPO_CX, y1: TOPO_CY, x2: x, y2: y, class: "topo-link",
    }));
  });

  // Controller hub
  svg.appendChild(svgEl("circle", {
    cx: TOPO_CX, cy: TOPO_CY, r: 34, class: "topo-controller-bg",
  }));
  svg.appendChild(svgEl("text", {
    x: TOPO_CX, y: TOPO_CY - 2, class: "topo-controller-label-inner",
  }, "CONTROLLER"));
  svg.appendChild(svgEl("text", {
    x: TOPO_CX, y: TOPO_CY + 12, class: "topo-controller-label-inner",
  }, "(server)"));

  // Nodes
  fabricNodes.forEach((node, i) => {
    const { x, y } = nodePosition(i, fabricNodes.length);
    _topoPositions[node.node_id] = { x, y };

    const stale = staleness(node.last_seen) > 30;
    svg.appendChild(svgEl("circle", {
      cx: x, cy: y, r: 22,
      class: `topo-node${stale ? " inactive" : ""}`,
      "data-node": node.node_id,
    }));
    svg.appendChild(svgEl("text", {
      x: x, y: y + 42, class: "topo-node-label",
    }, node.node_id));
    svg.appendChild(svgEl("text", {
      x: x, y: y + 56, class: "topo-node-sub",
    }, node.ip));
  });
}

// -------------------------------------------------------------------------
// Pulse animation triggered by new events
// -------------------------------------------------------------------------
const _seenEventIds = new Set();
let _firstPoll = true;

function pulseNewEvents() {
  // On first poll, just seed the set so we don't fire pulses for backlog
  if (_firstPoll) {
    for (const e of _events) _seenEventIds.add(e.event_id);
    _firstPoll = false;
    return;
  }

  const actionClass = { allowed: "allow", blocked: "block", reported: "report" };
  const svg = document.getElementById("topology");
  if (!svg) return;

  for (const e of _events) {
    if (_seenEventIds.has(e.event_id)) continue;
    _seenEventIds.add(e.event_id);

    const pos = _topoPositions[e.node_id];
    if (!pos) continue;

    const cls = actionClass[e.action] || "allow";
    const ring = svgEl("circle", {
      cx: pos.x, cy: pos.y, r: 22,
      class: `topo-pulse topo-pulse--${cls}`,
    });
    svg.appendChild(ring);
    ring.addEventListener("animationend", () => ring.remove());
  }

  // Prevent the set from growing unbounded
  if (_seenEventIds.size > 2000) {
    const keep = new Set(_events.map(e => e.event_id));
    _seenEventIds.clear();
    keep.forEach(id => _seenEventIds.add(id));
  }
}

// -------------------------------------------------------------------------
// Dashboard counters
// -------------------------------------------------------------------------
const _prevStats = { allowed: 0, blocked: 0, reported: 0, nodes: 0, rules: 0 };

function setTile(id, value, key) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = value;
  if (key && _prevStats[key] !== value) {
    el.parentElement.classList.remove("pulse");
    void el.parentElement.offsetWidth; // restart animation
    el.parentElement.classList.add("pulse");
    _prevStats[key] = value;
  }
}

function timeAgo(iso) {
  if (!iso) return "—";
  const secs = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 5)   return "just now";
  if (secs < 60)  return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}

function updateDashboard() {
  // Counts from events (server returns up to 200 most recent)
  let allowed = 0, blocked = 0, reported = 0;
  for (const e of _events) {
    if (e.action === "allowed")  allowed++;
    else if (e.action === "blocked")  blocked++;
    else if (e.action === "reported") reported++;
  }

  // Active = last_seen within 30 s, and not revoked
  const activeNodes = _nodes.filter(n => n.status !== "revoked" && staleness(n.last_seen) <= 30).length;
  const activeRules = _rules.filter(r => r.enabled).length;
  const last        = _events.length ? _events[_events.length - 1].timestamp : null;

  setTile("statAllowed",   allowed,   "allowed");
  setTile("statBlocked",   blocked,   "blocked");
  setTile("statReported",  reported,  "reported");
  setTile("statNodes",     activeNodes, "nodes");
  setTile("statRules",     activeRules, "rules");
  setTile("statLastEvent", timeAgo(last));
}

// Refresh "time ago" every second so it stays current between polls
setInterval(() => {
  const last = _events.length ? _events[_events.length - 1].timestamp : null;
  const el = document.getElementById("statLastEvent");
  if (el) el.textContent = timeAgo(last);
}, 1000);

// -------------------------------------------------------------------------
// Boot: initial load + polling (5 s)
// -------------------------------------------------------------------------
pollAll();
setInterval(pollAll, 5000);
