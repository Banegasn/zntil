"use strict";
const $ = (id) => document.getElementById(id),
  copy = (v) => structuredClone(v);
let state,
  draft,
  view = "overview",
  editing = null,
  busy = false;
function el(tag, text, cls) {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
}
function button(text, fn, cls = "button secondary") {
  const b = el("button", text, cls);
  b.type = "button";
  b.addEventListener("click", fn);
  return b;
}
function notice(text) {
  $("banner").textContent = text;
  $("banner").hidden = !text;
}
async function api(path, method = "GET", body) {
  const r = await fetch("/_zntil/admin/" + path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = r.status === 204 ? {} : await r.json();
  if (!r.ok) {
    if (r.status === 401) showLogin();
    throw Error(data.error || "Request failed");
  }
  return data;
}
function showLogin() {
  $("boot").hidden = true;
  $("app").hidden = true;
  $("login").hidden = false;
}
function accept(s) {
  $("connection").textContent = "Live · 5s";
  state = s;
  draft = null;
  $("boot").hidden = true;
  $("login").hidden = true;
  $("app").hidden = false;
  render();
}
async function refresh() {
  try {
    const s = await api("state");
    if (!state) {
      accept(s);
    } else {
      state = s;
      if (!draft) render();
    }
    $("connection").textContent = "Live · 5s";
  } catch (e) {
    $("connection").textContent = "Disconnected";
    if (state) {
      notice(e.message);
    } else {
      showLogin();
      $("login-error").textContent = e.message;
      $("login-error").hidden = false;
    }
  }
}
function dirty() {
  draft ??= {
    revision: state.revision,
    servers: copy(state.servers),
    proxies: copy(state.proxies),
  };
  return draft;
}
function table(headers, rows) {
  const t = el("table");
  const head = el("thead"),
    tr = el("tr");
  headers.forEach((x) => tr.append(el("th", x)));
  head.append(tr);
  t.append(head);
  const body = el("tbody");
  rows.forEach((row) => {
    const r = el("tr");
    row.forEach((v) => {
      const td = el("td");
      td.append(v instanceof Node ? v : el("span", String(v)));
      r.append(td);
    });
    body.append(r);
  });
  t.append(body);
  const wrap = el("div", undefined, "table-wrap");
  wrap.append(t);
  return wrap;
}
function section(title, description) {
  const h = el("div", undefined, "page-heading");
  const text = el("div");
  text.append(el("h1", title), el("p", description, "muted"));
  h.append(text);
  $("content").append(h);
  return h;
}
function panel(title) {
  const p = el("section", undefined, "panel");
  p.append(el("h2", title));
  $("content").append(p);
  return p;
}
function timestamp(n) {
  return new Date(n * 1000).toLocaleString();
}
function render() {
  if (!state) return;
  const s = draft || state;
  $("content").replaceChildren();
  $("breadcrumb").textContent = {
    overview: "Overview",
    activity: "Activity",
    servers: "Servers",
    proxies: "Proxies & domains",
    history: "History",
  }[view];
  $("mode-badge").textContent = state.mode;
  $("revision-label").textContent =
    "Revision " +
    state.revision +
    " · " +
    (state.persisted ? "Saved to disk" : "Memory only");
  $("draft-bar").hidden = !draft;
  document
    .querySelectorAll("[data-view]")
    .forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  if (view === "overview") {
    section(
      "Your traffic, in focus.",
      "Requests reaching the gateway since its last restart. CDN cache hits are counted at the edge separately.",
    );
    const cards = el("div", undefined, "stats-grid");
    for (const [label, key] of [
      ["Requests", "requests"],
      ["Blocked", "blocked"],
      ["Observed", "observed"],
      ["Errors", "errors"],
      ["In flight", "inflight"],
    ]) {
      const c = el("div", undefined, "stat-card");
      c.append(
        el("p", label, "muted"),
        el("h2", Number(state.counters[key] || 0).toLocaleString()),
      );
      cards.append(c);
    }
    $("content").append(cards);
    const p = panel("Traffic per minute");
    p.append(
      table(
        ["Time", "Requests", "Blocked", "Errors"],
        state.traffic
          .slice(-12)
          .map((t) => [timestamp(t.minute), t.requests, t.blocked, t.errors]),
      ),
    );
    const info = panel("Gateway status");
    info.append(
      el(
        "p",
        s.servers.length +
          " servers · " +
          s.proxies.length +
          " proxies · uptime " +
          Math.floor(state.uptime_seconds / 60) +
          " minutes",
      ),
    );
    state.warnings.forEach((w) => info.append(el("p", w, "muted")));
  }
  if (view === "activity") {
    section(
      "Recent decisions",
      "A bounded sample of allowed requests and recent exceptional decisions. No request paths, contents, IP addresses or user agents are stored here.",
    );
    panel("Activity").append(
      table(
        ["Time", "Domain", "Method", "Status", "Decision", "Reason", "Latency"],
        state.events.map((e) => [
          timestamp(e.time),
          e.host,
          e.method,
          e.status,
          e.outcome,
          e.reason,
          e.latency_ms + " ms",
        ]),
      ),
    );
  }
  if (view === "servers") {
    const h = section(
      "Upstream servers",
      "Connect services through private Railway networking or HTTPS origins.",
    );
    h.append(button("Add server", () => serverEditor()));
    panel("Servers").append(
      table(
        ["Name", "Address", "Transport", "Actions"],
        s.servers.map((server) => {
          const a = el("div", undefined, "actions");
          a.append(
            button("Edit", () => serverEditor(server)),
            button("Remove", () => {
              if (s.proxies.some((p) => p.server_id === server.id)) {
                notice("Remove or reassign this server’s proxies first.");
                return;
              }
              if (confirm("Remove " + server.name + " from the draft?")) {
                dirty().servers = dirty().servers.filter(
                  (x) => x.id !== server.id,
                );
                render();
              }
            }),
          );
          return [
            server.name,
            server.host + ":" + server.port,
            server.tls ? "HTTPS" : "HTTP",
            a,
          ];
        }),
      ),
    );
  }
  if (view === "proxies") {
    const h = section(
      "Proxies & domains",
      "Route multiple domains through one gateway. Adding a domain here also requires DNS and Railway domain / HTTPS setup.",
    );
    h.append(button("Add proxy", () => proxyEditor()));
    panel("Routes").append(
      table(
        ["Name", "Domains", "Upstream", "State", "Actions"],
        s.proxies.map((p) => {
          const a = el("div", undefined, "actions");
          a.append(
            button("Edit", () => proxyEditor(p)),
            button("Remove", () => {
              if (
                confirm(
                  "Remove " +
                    p.name +
                    " from the draft? Traffic changes only after Apply.",
                )
              ) {
                dirty().proxies = dirty().proxies.filter((x) => x.id !== p.id);
                render();
              }
            }),
          );
          return [
            p.name,
            p.route.hosts.join(", "),
            s.servers.find((x) => x.id === p.server_id)?.name || "Missing",
            p.enabled ? "Enabled" : "Disabled",
            a,
          ];
        }),
      ),
    );
  }
  if (view === "history") {
    section(
      "Configuration history",
      "Restore a saved revision as a new configuration. Traffic and sessions stay in memory only.",
    );
    panel("Saved revisions").append(
      table(
        ["Revision", "Saved", "Change", "Action"],
        state.history
          .filter((h) => h.revision !== state.revision)
          .map((h) => [
            h.revision,
            timestamp(h.created_at),
            h.summary,
            button("Restore", async () => {
              if (draft) {
                notice("Apply or discard your draft before restoring.");
                return;
              }
              if (confirm("Restore revision " + h.revision + "?"))
                try {
                  accept(
                    await api("rollback", "POST", {
                      revision: h.revision,
                      current_revision: state.revision,
                    }),
                  );
                  notice("Revision restored.");
                } catch (e) {
                  notice(e.message);
                }
            }),
          ]),
      ),
    );
  }
}
function serverEditor(s) {
  editing = s?.id || null;
  $("server-title").textContent = s ? "Edit server" : "Add server";
  for (const [id, v] of [
    ["server-name", s?.name || ""],
    ["server-host", s?.host || ""],
    ["server-port", s?.port || 8080],
    ["server-origin-token", s?.origin_token_env || ""],
  ])
    $(id).value = v;
  $("server-tls").checked = s?.tls || false;
  $("server-error").hidden = true;
  $("server-dialog").showModal();
}
const fields = {
  "proxy-name": "name",
  "proxy-upstream-host": "upstream_host",
  "proxy-forwarded-host": "forwarded_host",
  "proxy-scheme": "public_scheme",
  "proxy-timeout": "upstream_timeout_seconds",
  "proxy-rate": "requests_per_second",
  "proxy-burst": "burst",
  "proxy-global-rate": "global_requests_per_second",
  "proxy-global-burst": "global_burst",
};
const defaults = {
  hosts: [],
  upstream: "placeholder",
  upstream_port: 8080,
  upstream_tls: false,
  upstream_host: null,
  forwarded_host: null,
  public_scheme: null,
  origin_token_env: null,
  body_inspection_exempt_prefixes: [],
  requests_per_second: 10,
  burst: 100,
  crawler_requests_per_second: 5,
  crawler_burst: 30,
  global_requests_per_second: 200,
  global_burst: 400,
  sensitive_prefixes: ["/login", "/admin", "/v1/auth"],
  sensitive_requests_per_second: 0.5,
  sensitive_burst: 10,
  deny_prefixes: [
    "/.git",
    "/.env",
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/vendor/phpunit",
  ],
  upstream_timeout_seconds: 60,
};
function proxyEditor(p) {
  editing = p?.id || null;
  const r = p?.route || defaults;
  $("proxy-title").textContent = p ? "Edit proxy" : "Add proxy";
  $("proxy-server").replaceChildren();
  (draft || state).servers.forEach((s) => {
    const o = el("option", s.name);
    o.value = s.id;
    $("proxy-server").append(o);
  });
  $("proxy-server").value =
    p?.server_id || (draft || state).servers[0]?.id || "";
  for (const [id, key] of Object.entries(fields))
    $(id).value = key === "name" ? p?.name || "" : (r[key] ?? "");
  $("proxy-enabled").checked = p?.enabled ?? true;
  $("proxy-domains").value = r.hosts.join("\n");
  $("proxy-sensitive").value = r.sensitive_prefixes.join("\n");
  $("proxy-exemptions").value = r.body_inspection_exempt_prefixes.join("\n");
  $("proxy-error").hidden = true;
  $("proxy-dialog").showModal();
}
const lines = (id) =>
  $(id)
    .value.split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
$("server-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const d = dirty();
  const s = {
    id: editing || "server-" + crypto.randomUUID(),
    name: $("server-name").value.trim(),
    host: $("server-host").value.trim().toLowerCase(),
    port: Number($("server-port").value),
    tls: $("server-tls").checked,
    origin_token_env: $("server-origin-token").value.trim() || null,
  };
  const i = d.servers.findIndex((x) => x.id === editing);
  if (i < 0) d.servers.push(s);
  else d.servers[i] = s;
  $("server-dialog").close();
  render();
});
$("proxy-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const d = dirty();
  const old = d.proxies.find((x) => x.id === editing);
  const route = copy(old?.route || defaults);
  for (const [id, key] of Object.entries(fields)) {
    if (key === "name") continue;
    route[key] =
      $(id).type === "number"
        ? Number($(id).value)
        : $(id).value.trim() || null;
  }
  route.hosts = lines("proxy-domains").map((h) => h.toLowerCase());
  route.sensitive_prefixes = lines("proxy-sensitive");
  route.body_inspection_exempt_prefixes = lines("proxy-exemptions");
  const p = {
    id: editing || "proxy-" + crypto.randomUUID(),
    name: $("proxy-name").value.trim(),
    server_id: $("proxy-server").value,
    enabled: $("proxy-enabled").checked,
    route,
  };
  const i = d.proxies.findIndex((x) => x.id === editing);
  if (i < 0) d.proxies.push(p);
  else d.proxies[i] = p;
  $("proxy-dialog").close();
  render();
});
document
  .querySelectorAll(".close-dialog")
  .forEach((b) =>
    b.addEventListener("click", () => b.closest("dialog").close()),
  );
document.querySelectorAll("[data-view]").forEach((b) =>
  b.addEventListener("click", () => {
    view = b.dataset.view;
    render();
  }),
);
$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("login-submit").disabled = true;
  try {
    await api("login", "POST", { token: $("access-key").value });
    $("access-key").value = "";
    accept(await api("state"));
  } catch (err) {
    $("login-error").textContent = err.message;
    $("login-error").hidden = false;
  } finally {
    $("login-submit").disabled = false;
  }
});
$("refresh").addEventListener("click", refresh);
$("logout").addEventListener("click", async () => {
  try {
    await api("logout", "POST", {});
    draft = null;
    state = null;
    showLogin();
  } catch (e) {
    notice(e.message);
  }
});
$("discard").addEventListener("click", () => {
  draft = null;
  notice("");
  render();
});
for (const [id, path, method] of [
  ["validate", "validate", "POST"],
  ["save", "config", "PUT"],
])
  $(id).addEventListener("click", async () => {
    if (!draft || busy) return;
    busy = true;
    $(id).disabled = true;
    try {
      const s = await api(path, method, draft);
      if (id === "save") accept(s);
      notice(
        id === "save"
          ? "Configuration applied and saved."
          : "Configuration is valid.",
      );
    } catch (e) {
      notice(e.message + " Your draft has been kept.");
    } finally {
      busy = false;
      $(id).disabled = false;
    }
  });
window.addEventListener("beforeunload", (e) => {
  if (draft) {
    e.preventDefault();
    e.returnValue = "";
  }
});
refresh();
setInterval(() => {
  if (!busy) refresh();
}, 5000);
