const express = require("express");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");

const app = express();
const PORT = 3000;
const db = new Database(path.join(__dirname, "student_portal.db"));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "local-academic-lab-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" }
  })
);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

const existing = db.prepare("SELECT COUNT(*) AS count FROM users").get();
if (existing.count === 0) {
  db.prepare(
    "INSERT INTO users (username, password, name, email) VALUES (?, ?, ?, ?)"
  ).run("student", "student123", "Demo Student", "student@example.com");
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).send("Please log in first.");
  next();
}

function csrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString("hex");
  }
  return req.session.csrfToken;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

app.get("/api/me", requireLogin, (req, res) => {
  const user = db.prepare(
    "SELECT id, username, name, email FROM users WHERE id = ?"
  ).get(req.session.user.id);
  res.json(user);
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

/*
 * SQL INJECTION DEMO
 * Vulnerable mode intentionally concatenates user input into SQL.
 * Secured mode uses a parameterized query.
 */
app.post("/api/sqli/vulnerable-login", (req, res) => {
  const { username = "", password = "" } = req.body;
  const query =
    `SELECT id, username, name, email FROM users ` +
    `WHERE username = '${username}' AND password = '${password}'`;

  try {
    const user = db.prepare(query).get();
    if (!user) return res.status(401).json({ ok: false, message: "Login failed." });
    req.session.user = user;
    res.json({ ok: true, message: "VULNERABLE login accepted.", user });
  } catch (err) {
    res.status(400).json({ ok: false, message: "SQL error: " + err.message });
  }
});

app.post("/api/sqli/secured-login", (req, res) => {
  const { username = "", password = "" } = req.body;
  const user = db.prepare(
    "SELECT id, username, name, email FROM users WHERE username = ? AND password = ?"
  ).get(username, password);

  if (!user) return res.status(401).json({ ok: false, message: "Login failed." });
  req.session.user = user;
  res.json({ ok: true, message: "SECURED login accepted.", user });
});

/*
 * OS COMMAND INJECTION DEMO
 * The vulnerable endpoint is intentionally limited to a local demo command.
 * It demonstrates why shell-string construction is unsafe without exposing
 * a remote shell or arbitrary server administration.
 */
app.post("/api/command/vulnerable", requireLogin, (req, res) => {
  const input = String(req.body.host || "");
  const cp = require("child_process");

  // Intentionally vulnerable academic example:
  // user input is concatenated into a shell command.
  const command = process.platform === "win32"
    ? `echo Checking ${input}`
    : `printf 'Checking %s\\n' ${input}`;

  cp.exec(command, { timeout: 2000 }, (error, stdout, stderr) => {
    res.json({
      ok: !error,
      mode: "vulnerable",
      output: (stdout || stderr || (error && error.message) || "").trim()
    });
  });
});

app.post("/api/command/secured", requireLogin, (req, res) => {
  const input = String(req.body.host || "").trim();

  // Mitigation: strict allow-list validation + no shell interpretation.
  if (!/^[A-Za-z0-9.-]{1,253}$/.test(input)) {
    return res.status(400).json({
      ok: false,
      mode: "secured",
      message: "Rejected: hostname contains disallowed characters."
    });
  }

  const cp = require("child_process");
  cp.execFile(
    process.platform === "win32" ? "cmd.exe" : "printf",
    process.platform === "win32" ? ["/c", "echo", `Checking ${input}`] : [`Checking ${input}\\n`],
    { timeout: 2000 },
    (error, stdout, stderr) => {
      res.json({
        ok: !error,
        mode: "secured",
        output: (stdout || stderr || (error && error.message) || "").trim()
      });
    }
  );
});

/*
 * STORED XSS DEMO
 * Vulnerable endpoint stores raw HTML. Secured endpoint stores the same
 * comment but the display route applies HTML escaping.
 */
app.post("/api/xss/vulnerable/comments", requireLogin, (req, res) => {
  const body = String(req.body.body || "");
  db.prepare(
    "INSERT INTO comments (username, body, created_at) VALUES (?, ?, datetime('now'))"
  ).run(req.session.user.username, body);
  res.json({ ok: true });
});

app.post("/api/xss/secured/comments", requireLogin, (req, res) => {
  const body = String(req.body.body || "");
  db.prepare(
    "INSERT INTO comments (username, body, created_at) VALUES (?, ?, datetime('now'))"
  ).run(req.session.user.username, body);
  res.json({ ok: true });
});

app.get("/api/xss/comments", requireLogin, (req, res) => {
  const mode = req.query.mode === "secured" ? "secured" : "vulnerable";
  const rows = db.prepare(
    "SELECT username, body, created_at FROM comments ORDER BY id DESC"
  ).all();

  if (mode === "secured") {
    return res.json({
      mode,
      comments: rows.map(r => ({ ...r, body: escapeHtml(r.body) }))
    });
  }
  res.json({ mode, comments: rows });
});

/*
 * POST CSRF DEMO
 * The vulnerable route accepts a state-changing POST without a CSRF token.
 * The secured route requires a synchronizer token tied to the user's session.
 */
app.get("/api/csrf/profile", requireLogin, (req, res) => {
  const user = db.prepare(
    "SELECT username, name, email FROM users WHERE id = ?"
  ).get(req.session.user.id);
  res.json({ ...user, csrfToken: csrfToken(req) });
});

app.post("/api/csrf/vulnerable/update-email", requireLogin, (req, res) => {
  const email = String(req.body.email || "");
  db.prepare("UPDATE users SET email = ? WHERE id = ?").run(
    email,
    req.session.user.id
  );
  res.json({ ok: true, mode: "vulnerable", message: "Email changed without CSRF verification." });
});

app.post("/api/csrf/secured/update-email", requireLogin, (req, res) => {
  const token = String(req.body.csrfToken || "");
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({
      ok: false,
      mode: "secured",
      message: "Blocked: invalid or missing CSRF token."
    });
  }

  const email = String(req.body.email || "");
  db.prepare("UPDATE users SET email = ? WHERE id = ?").run(
    email,
    req.session.user.id
  );
  res.json({ ok: true, mode: "secured", message: "Email changed after CSRF verification." });
});

app.listen(PORT, () => {
  console.log(`SecureStudent lab running at http://localhost:${PORT}`);
  console.log("Demo account: student / student123");
});
