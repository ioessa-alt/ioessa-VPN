const $ = (id) => document.getElementById(id);
let token = null;
try { token = sessionStorage.getItem("vpnToken"); } catch (_) { /* storage blocked */ }
let timer = null;
let connected = false;

async function api(path, method = "GET", body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== "/api/login") {
    signOut(true);
    throw new Error("Session expired, please sign in again");
  }
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function fmtBytes(n) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + units[i];
}

function fmtUptime(s) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return [h, m, sec].map((v) => String(v).padStart(2, "0")).join(":");
}

function render(s) {
  connected = !!s.connected;
  $("dot").classList.toggle("on", connected);
  $("state").textContent = connected ? "Connected" : "Disconnected";
  $("toggle").textContent = connected ? "Disconnect" : "Connect";
  $("server").disabled = connected;
  $("details").classList.toggle("hidden", !connected);
  if (connected) {
    $("city").textContent = s.city;
    $("vip").textContent = s.vip;
    $("uptime").textContent = fmtUptime(s.uptime);
    $("rx").textContent = fmtBytes(s.rx);
    $("tx").textContent = fmtBytes(s.tx);
  }
}

async function refresh() {
  try { render(await api("/api/status")); $("dashErr").textContent = ""; }
  catch (e) { $("dashErr").textContent = e.message; }
}

function showDash() {
  $("login").classList.add("hidden");
  $("dash").classList.remove("hidden");
  clearInterval(timer);
  timer = setInterval(refresh, 2000);
  refresh();
}

function showLogin() {
  clearInterval(timer);
  $("dash").classList.add("hidden");
  $("login").classList.remove("hidden");
}

async function loadServers() {
  const list = await api("/api/servers");
  const sel = $("server");
  sel.replaceChildren(...list.map((s) => {
    const o = document.createElement("option");
    o.value = s.id;
    o.textContent = s.city + " (" + s.id + ")";
    return o;
  }));
}

$("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("loginBtn").disabled = true;
  $("loginErr").textContent = "";
  try {
    const data = await api("/api/login", "POST", {
      username: $("user").value, password: $("pass").value,
    });
    token = data.token;
    try { sessionStorage.setItem("vpnToken", token); } catch (_) {}
    $("pass").value = "";
    await loadServers();
    showDash();
  } catch (err) {
    $("loginErr").textContent = err.message;
  } finally {
    $("loginBtn").disabled = false;
  }
});

$("toggle").addEventListener("click", async () => {
  const wasConnected = connected;
  const busy = wasConnected ? "Disconnecting…" : "Connecting…";
  $("toggle").disabled = true;
  $("state").textContent = busy;
  $("toggle").textContent = busy;
  $("dashErr").textContent = "";
  try {
    const s = wasConnected
      ? await api("/api/disconnect", "POST", {})
      : await api("/api/connect", "POST", { server: $("server").value });
    render(s);
  } catch (err) {
    $("dashErr").textContent = err.message;
    refresh();
  } finally {
    $("toggle").disabled = false;
  }
});

async function signOut(silent) {
  if (!silent && token) {
    try { await api("/api/logout", "POST", {}); } catch (_) {}
  }
  token = null;
  try { sessionStorage.removeItem("vpnToken"); } catch (_) {}
  showLogin();
}

$("logout").addEventListener("click", () => signOut(false));

// Resume an existing session on reload.
if (token) {
  loadServers().then(showDash).catch(() => signOut(true));
} else {
  showLogin();
}
