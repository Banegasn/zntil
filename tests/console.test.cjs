const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(
  new URL("../console/app.js", `file://${__filename}`),
  "utf8",
);
class Element {
  constructor() {
    this.hidden = false;
    this.children = [];
    this.classList = { toggle() {} };
  }
  append(...nodes) {
    this.children.push(...nodes);
  }
  replaceChildren(...nodes) {
    this.children = nodes;
  }
  addEventListener() {}
}
const snapshot = {
  revision: 1,
  persisted: true,
  mode: "enforce",
  counters: { requests: 1 },
  traffic: [],
  events: [],
  servers: [],
  proxies: [],
  history: [],
  warnings: [],
  uptime_seconds: 1,
};
async function boot(fetch) {
  const nodes = new Map();
  const document = {
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, new Element());
      return nodes.get(id);
    },
    createElement() {
      return new Element();
    },
    querySelectorAll() {
      return [];
    },
  };
  document.getElementById("app").hidden = true;
  document.getElementById("login").hidden = true;
  const ctx = vm.createContext({
    document,
    Node: Element,
    structuredClone,
    fetch,
    window: { addEventListener() {} },
    setInterval() {},
  });
  vm.runInContext(source, ctx);
  await new Promise(setImmediate);
  return { nodes, ctx };
}
const response = (status, value) => ({
  ok: status === 200,
  status,
  json: async () => structuredClone(value),
});
test("a valid session on page reload leaves boot and shows dashboard", async () => {
  const { nodes } = await boot(async () => response(200, snapshot));
  assert.equal(nodes.get("boot").hidden, true);
  assert.equal(nodes.get("login").hidden, true);
  assert.equal(nodes.get("app").hidden, false);
  assert.equal(nodes.get("connection").textContent, "Live · 5s");
});
test("an expired session shows login instead of boot", async () => {
  const { nodes } = await boot(async () =>
    response(401, { error: "Sign in to the management console." }),
  );
  assert.equal(nodes.get("boot").hidden, true);
  assert.equal(nodes.get("login").hidden, false);
  assert.equal(nodes.get("app").hidden, true);
});
test("a startup network failure shows a recoverable login error", async () => {
  const { nodes } = await boot(async () => {
    throw Error("Network unavailable");
  });
  assert.equal(nodes.get("boot").hidden, true);
  assert.equal(nodes.get("login").hidden, false);
  assert.equal(nodes.get("login-error").textContent, "Network unavailable");
});
test("polling preserves an unapplied draft", async () => {
  const { ctx } = await boot(async () => response(200, snapshot));
  vm.runInContext('dirty().servers.push({id:"draft-server"});', ctx);
  await vm.runInContext("refresh()", ctx);
  assert.equal(vm.runInContext("draft.servers[0].id", ctx), "draft-server");
});
