import { mount, components as C } from "/node_modules/@anentrypoint/design/src/index.js";

const state = {
  users: [],
  upstreams: [],
  selectedUserId: null,
  keys: [],
  newUpstream: { name: "", baseUrl: "", kind: "static", injectName: "Authorization", injectTemplate: "Bearer {token}", descriptorExtra: "{}", secret: "" },
};

async function api(path, opts) {
  const res = await fetch(`/api${path}`, {
    method: opts?.method ?? "GET",
    headers: opts?.body ? { "content-type": "application/json" } : undefined,
    body: opts?.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) throw new Error((await res.json()).error ?? res.statusText);
  return res.json();
}

async function refresh() {
  state.users = await api("/users");
  state.upstreams = await api("/upstreams");
  if (state.selectedUserId) state.keys = await api(`/keys?userId=${state.selectedUserId}`).catch(() => []);
  render();
}

function buildDescriptor(f) {
  const extra = JSON.parse(f.descriptorExtra || "{}");
  return {
    kind: f.kind,
    inject: { location: "header", name: f.injectName, template: f.injectTemplate },
    ...extra,
  };
}

function UpstreamForm() {
  const f = state.newUpstream;
  return C.Panel({
    title: "add upstream",
    children: C.Form({
      submit: "create upstream",
      onSubmit: async () => {
        await api("/upstreams", {
          method: "POST",
          body: { name: f.name, baseUrl: f.baseUrl, authDescriptor: buildDescriptor(f), secret: f.secret },
        });
        state.newUpstream = { name: "", baseUrl: "", kind: "static", injectName: "Authorization", injectTemplate: "Bearer {token}", descriptorExtra: "{}", secret: "" };
        await refresh();
      },
      fields: [
        C.TextField({ label: "name", value: f.name, onInput: (e) => (f.name = e.target.value) }),
        C.TextField({ label: "base url", value: f.baseUrl, onInput: (e) => (f.baseUrl = e.target.value) }),
        C.Select({
          label: "auth kind",
          value: f.kind,
          options: ["static", "bearer_passthrough", "oauth2_client_credentials", "oauth2_authcode", "device_code"].map((k) => [k, k]),
          onChange: (e) => (f.kind = e.target.value),
        }),
        C.TextField({ label: "inject header name", value: f.injectName, onInput: (e) => (f.injectName = e.target.value) }),
        C.TextField({ label: "inject template", value: f.injectTemplate, hint: "use {token} as placeholder", onInput: (e) => (f.injectTemplate = e.target.value) }),
        C.TextField({ label: "descriptor extra (JSON)", value: f.descriptorExtra, multiline: true, rows: 4, hint: "merged into the descriptor, e.g. oauth2.token_url/client_id", onInput: (e) => (f.descriptorExtra = e.target.value) }),
        C.TextField({ label: "secret / client secret", value: f.secret, type: "password", onInput: (e) => (f.secret = e.target.value) }),
      ],
    }),
  });
}

function UpstreamsTable() {
  return C.Panel({
    title: "upstreams",
    count: state.upstreams.length,
    children: C.Table({
      headers: ["name", "base url", "auth kind"],
      rows: state.upstreams.map((u) => [u.name, u.base_url, u.auth_descriptor.kind]),
      emptyText: "no upstreams yet",
    }),
  });
}

function UsersPanel() {
  return C.Panel({
    title: "users",
    count: state.users.length,
    right: C.Btn({
      children: "new user",
      onClick: async () => {
        const email = prompt("email (optional)");
        await api("/users", { method: "POST", body: { email } });
        await refresh();
      },
    }),
    children: C.Table({
      headers: ["id", "email"],
      rows: state.users.map((u) => [u.id.slice(0, 8), u.email ?? ""]),
      onRowClick: (row, i) => {
        state.selectedUserId = state.users[i].id;
        refresh();
      },
    }),
  });
}

function KeysPanel() {
  if (!state.selectedUserId) return C.Panel({ title: "api keys", children: "select a user" });
  return C.Panel({
    title: "api keys",
    right: C.Btn({
      children: "new key",
      onClick: async () => {
        const name = prompt("key name") ?? "default";
        const { rawKey } = await api("/keys", { method: "POST", body: { userId: state.selectedUserId, name } });
        alert(`save this now, shown once:\n${rawKey}`);
        await refresh();
      },
    }),
    children: C.Table({
      headers: ["name", "prefix", "revoked"],
      rows: (state.keys ?? []).map((k) => [k.name, k.key_prefix, k.revoked_at ? "yes" : "no"]),
      emptyText: "no keys",
    }),
  });
}

function render() {
  mount(document.getElementById("app"), () =>
    C.AppShell({
      topbar: C.Topbar({ brand: "okeydokey", leaf: "key gateway" }),
      main: [
        C.PageHeader({ title: "okeydokey", lede: "generalized bearer-key gateway for any upstream API" }),
        UsersPanel(),
        KeysPanel(),
        UpstreamsTable(),
        UpstreamForm(),
      ],
    })
  );
}

refresh();
