const { Pool } = require("pg");
const crypto = require("crypto");

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error("FATAL: variável DATABASE_URL não definida.");
}

// Railway internal Postgres não usa SSL. Se apontar para a URL pública, defina PGSSL=require.
const pool = new Pool({
  connectionString,
  ssl: process.env.PGSSL === "require" ? { rejectUnauthorized: false } : false,
});

// ---------- Senhas (scrypt, sem dependência nativa) ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(pw, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [salt, hash] = stored.split(":");
  const test = crypto.scryptSync(pw, salt, 64).toString("hex");
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(test, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- Schema + seed ----------
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      estimate INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS time_sessions (
      id SERIAL PRIMARY KEY,
      task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      seconds INTEGER NOT NULL,
      completed BOOLEAN NOT NULL DEFAULT false,
      started_at TIMESTAMPTZ NOT NULL,
      ended_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sessions_started ON time_sessions(started_at);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON time_sessions(user_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id);`);

  // Seed do admin a partir das variáveis de ambiente
  const adminUser = (process.env.ADMIN_USER || "admin").trim();
  const adminPass = process.env.ADMIN_PASS || "admin";
  const { rows } = await pool.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
  if (rows.length === 0) {
    await pool.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1,$2,'admin') ON CONFLICT (username) DO NOTHING",
      [adminUser, hashPassword(adminPass)]
    );
    console.log(`Admin inicial criado: usuário "${adminUser}"`);
  }
}

module.exports = { pool, init, hashPassword, verifyPassword };
