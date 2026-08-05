const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { pool, init, hashPassword, verifyPassword } = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const SESSION_DAYS = 7;

app.use(express.json());
app.disable("x-powered-by");

// ---------- Sessão via cookie assinado (stateless) ----------
function sign(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const mac = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");
  return `${payload}.${mac}`;
}
function unsign(token) {
  if (!token || !token.includes(".")) return null;
  const [payload, mac] = token.split(".");
  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const obj = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (obj.exp && Date.now() > obj.exp) return null;
    return obj;
  } catch {
    return null;
  }
}
function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(";").forEach((c) => {
    const i = c.indexOf("=");
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}
function setSession(res, user) {
  const token = sign({
    uid: user.id,
    username: user.username,
    role: user.role,
    exp: Date.now() + SESSION_DAYS * 86400 * 1000,
  });
  res.setHeader(
    "Set-Cookie",
    `sid=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`
  );
}
function clearSession(res) {
  res.setHeader("Set-Cookie", "sid=; HttpOnly; Path=/; Max-Age=0");
}

app.use((req, res, next) => {
  const cookies = parseCookies(req);
  req.user = unsign(cookies.sid);
  next();
});
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Não autenticado" });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Não autenticado" });
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Apenas o admin pode fazer isso" });
  next();
}

// ---------- Auth ----------
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: "Informe usuário e senha" });
  const { rows } = await pool.query(
    "SELECT * FROM users WHERE username=$1",
    [String(username).trim()]
  );
  const u = rows[0];
  if (!u || !verifyPassword(password, u.password_hash))
    return res.status(401).json({ error: "Usuário ou senha inválidos" });
  setSession(res, u);
  res.json({ id: u.id, username: u.username, role: u.role });
});

app.post("/api/logout", (req, res) => {
  clearSession(res);
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ id: req.user.uid, username: req.user.username, role: req.user.role });
});

// ---------- Usuários (admin) ----------
app.get("/api/users", requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id, username, role, created_at FROM users ORDER BY role DESC, username ASC"
  );
  res.json(rows);
});

app.post("/api/users", requireAdmin, async (req, res) => {
  let { username, password, role } = req.body || {};
  username = String(username || "").trim();
  role = role === "admin" ? "admin" : "user";
  if (!username || !password)
    return res.status(400).json({ error: "Informe usuário e senha" });
  if (String(password).length < 4)
    return res.status(400).json({ error: "A senha precisa ter ao menos 4 caracteres" });
  try {
    const { rows } = await pool.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3) RETURNING id, username, role, created_at",
      [username, hashPassword(password), role]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    if (e.code === "23505")
      return res.status(409).json({ error: "Esse nome de usuário já existe" });
    throw e;
  }
});

app.patch("/api/users/:id/password", requireAdmin, async (req, res) => {
  const { password } = req.body || {};
  if (!password || String(password).length < 4)
    return res.status(400).json({ error: "A senha precisa ter ao menos 4 caracteres" });
  const r = await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [
    hashPassword(password),
    req.params.id,
  ]);
  if (r.rowCount === 0) return res.status(404).json({ error: "Usuário não encontrado" });
  res.json({ ok: true });
});

app.delete("/api/users/:id", requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.user.uid)
    return res.status(400).json({ error: "Você não pode excluir a si mesmo" });
  const r = await pool.query("DELETE FROM users WHERE id=$1", [id]);
  if (r.rowCount === 0) return res.status(404).json({ error: "Usuário não encontrado" });
  res.json({ ok: true });
});

// ---------- Tarefas ----------
// GET: usuário vê as próprias; admin vê todas (ou filtra por ?user_id=)
app.get("/api/tasks", requireAuth, async (req, res) => {
  const isAdmin = req.user.role === "admin";
  const params = [];
  let where = "";
  if (isAdmin) {
    if (req.query.user_id) {
      params.push(req.query.user_id);
      where = `WHERE t.user_id = $1`;
    }
  } else {
    params.push(req.user.uid);
    where = `WHERE t.user_id = $1`;
  }
  const { rows } = await pool.query(
    `SELECT t.id, t.title, t.estimate, t.status, t.user_id, t.created_at,
            u.username AS owner,
            COALESCE(SUM(s.seconds),0)::int AS total_seconds,
            COALESCE(SUM(CASE WHEN s.completed THEN 1 ELSE 0 END),0)::int AS pomos_done
       FROM tasks t
       JOIN users u ON u.id = t.user_id
       LEFT JOIN time_sessions s ON s.task_id = t.id
       ${where}
       GROUP BY t.id, u.username
       ORDER BY (t.status='done'), t.created_at DESC`,
    params
  );
  res.json(rows);
});

// POST: usuário e admin podem adicionar. Usuário cria para si; admin pode criar para outro via user_id.
app.post("/api/tasks", requireAuth, async (req, res) => {
  let { title, estimate, user_id } = req.body || {};
  title = String(title || "").trim();
  estimate = Math.max(1, Math.min(50, parseInt(estimate) || 1));
  if (!title) return res.status(400).json({ error: "Informe o nome da tarefa" });
  let owner = req.user.uid;
  if (req.user.role === "admin" && user_id) owner = parseInt(user_id);
  const { rows } = await pool.query(
    "INSERT INTO tasks (user_id, title, estimate) VALUES ($1,$2,$3) RETURNING *",
    [owner, title, estimate]
  );
  res.status(201).json(rows[0]);
});

// PATCH (editar / concluir): SOMENTE admin
app.patch("/api/tasks/:id", requireAdmin, async (req, res) => {
  const { title, estimate, status } = req.body || {};
  const fields = [];
  const params = [];
  let i = 1;
  if (title !== undefined) {
    fields.push(`title=$${i++}`);
    params.push(String(title).trim());
  }
  if (estimate !== undefined) {
    fields.push(`estimate=$${i++}`);
    params.push(Math.max(1, Math.min(50, parseInt(estimate) || 1)));
  }
  if (status !== undefined) {
    fields.push(`status=$${i++}`);
    params.push(status === "done" ? "done" : "active");
  }
  if (!fields.length) return res.status(400).json({ error: "Nada para atualizar" });
  params.push(req.params.id);
  const r = await pool.query(
    `UPDATE tasks SET ${fields.join(", ")} WHERE id=$${i} RETURNING *`,
    params
  );
  if (r.rowCount === 0) return res.status(404).json({ error: "Tarefa não encontrada" });
  res.json(r.rows[0]);
});

// DELETE: SOMENTE admin
app.delete("/api/tasks/:id", requireAdmin, async (req, res) => {
  const r = await pool.query("DELETE FROM tasks WHERE id=$1", [req.params.id]);
  if (r.rowCount === 0) return res.status(404).json({ error: "Tarefa não encontrada" });
  res.json({ ok: true });
});

// ---------- Registro de tempo ----------
// Dono da tarefa (ou admin) registra o tempo trabalhado. Isso NÃO edita a tarefa.
app.post("/api/tasks/:id/sessions", requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.id);
  const { seconds, completed, started_at, ended_at } = req.body || {};
  const sec = parseInt(seconds);
  if (!sec || sec < 1) return res.status(400).json({ error: "Tempo inválido" });
  const { rows } = await pool.query("SELECT user_id FROM tasks WHERE id=$1", [taskId]);
  if (!rows.length) return res.status(404).json({ error: "Tarefa não encontrada" });
  if (req.user.role !== "admin" && rows[0].user_id !== req.user.uid)
    return res.status(403).json({ error: "Tarefa de outro usuário" });
  const start = started_at ? new Date(started_at) : new Date(Date.now() - sec * 1000);
  const end = ended_at ? new Date(ended_at) : new Date();
  await pool.query(
    "INSERT INTO time_sessions (task_id, user_id, seconds, completed, started_at, ended_at) VALUES ($1,$2,$3,$4,$5,$6)",
    [taskId, rows[0].user_id, sec, !!completed, start, end]
  );
  res.status(201).json({ ok: true });
});

// ---------- Histórico (admin) ----------
app.get("/api/history", requireAdmin, async (req, res) => {
  const { from, to, user_id } = req.query;
  const params = [];
  const conds = [];
  if (from) {
    params.push(from + " 00:00:00");
    conds.push(`s.started_at >= $${params.length}`);
  }
  if (to) {
    params.push(to + " 23:59:59.999");
    conds.push(`s.started_at <= $${params.length}`);
  }
  if (user_id) {
    params.push(user_id);
    conds.push(`s.user_id = $${params.length}`);
  }
  const where = conds.length ? "WHERE " + conds.join(" AND ") : "";

  const summary = await pool.query(
    `SELECT u.id AS user_id, u.username, t.id AS task_id, t.title, t.status,
            SUM(s.seconds)::int AS total_seconds,
            SUM(CASE WHEN s.completed THEN 1 ELSE 0 END)::int AS pomodoros,
            COUNT(s.id)::int AS sessions,
            MIN(s.started_at) AS first_at, MAX(s.ended_at) AS last_at
       FROM time_sessions s
       JOIN users u ON u.id = s.user_id
       JOIN tasks t ON t.id = s.task_id
       ${where}
       GROUP BY u.id, u.username, t.id, t.title, t.status
       ORDER BY u.username ASC, total_seconds DESC`,
    params
  );

  const detail = await pool.query(
    `SELECT s.id, u.username, t.title, s.seconds, s.completed, s.started_at, s.ended_at
       FROM time_sessions s
       JOIN users u ON u.id = s.user_id
       JOIN tasks t ON t.id = s.task_id
       ${where}
       ORDER BY s.started_at DESC
       LIMIT 500`,
    params
  );

  res.json({ summary: summary.rows, detail: detail.rows });
});

// ---------- Páginas / estáticos ----------
const PUB = path.join(__dirname, "public");
app.use(express.static(PUB));

app.get("/", (req, res) => {
  if (!req.user) return res.redirect("/login.html");
  res.redirect("/app.html");
});

// Guarda de páginas admin
["/admin.html", "/history.html"].forEach((p) => {
  app.get(p, (req, res, next) => {
    if (!req.user) return res.redirect("/login.html");
    if (req.user.role !== "admin") return res.redirect("/app.html");
    next();
  });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Erro interno" });
});

init()
  .then(() => {
    app.listen(PORT, () => console.log(`Pomofocus rodando na porta ${PORT}`));
  })
  .catch((e) => {
    console.error("Falha ao iniciar (DB):", e.message);
    process.exit(1);
  });
