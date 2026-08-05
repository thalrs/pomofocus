// Utilitários compartilhados do frontend
async function api(path, options = {}) {
  const opt = Object.assign({ headers: {} }, options);
  if (opt.body && typeof opt.body !== "string") {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(opt.body);
  }
  const res = await fetch(path, opt);
  if (res.status === 401) {
    location.href = "/login.html";
    throw new Error("Não autenticado");
  }
  let data = null;
  try { data = await res.json(); } catch {}
  if (!res.ok) throw new Error((data && data.error) || "Erro na requisição");
  return data;
}

function toast(msg, isErr = false) {
  let t = document.getElementById("toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.className = isErr ? "err show" : "show";
  clearTimeout(t._timer);
  t._timer = setTimeout(() => (t.className = ""), 2800);
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

// Formata segundos como "1h 23m" ou "5m 10s"
function fmtDuration(sec) {
  sec = Math.round(sec || 0);
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function fmtDateTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", year: "2-digit", hour: "2-digit", minute: "2-digit" });
}

async function getMe() {
  try { return await api("/api/me"); }
  catch { return null; }
}

function renderNav(me, active) {
  const isAdmin = me && me.role === "admin";
  const links = [`<a href="/app.html" class="${active==='app'?'active':''}">Timer</a>`];
  if (isAdmin) {
    links.push(`<a href="/admin.html" class="${active==='admin'?'active':''}">Painel Admin</a>`);
    links.push(`<a href="/history.html" class="${active==='history'?'active':''}">Histórico</a>`);
  }
  links.push(`<span class="pill">${escapeHtml(me ? me.username : "")}${isAdmin ? " · admin" : ""}</span>`);
  links.push(`<button id="logoutBtn">Sair</button>`);
  const nav = document.getElementById("nav");
  nav.innerHTML = `
    <div class="brand">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="13" r="8"/><path d="M12 13V9M12 5V3M9 3h6"/></svg>
      Pomofocus
    </div>
    <div class="nav-links">${links.join("")}</div>`;
  document.getElementById("logoutBtn").onclick = async () => {
    await api("/api/logout", { method: "POST" });
    location.href = "/login.html";
  };
}
