const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");

if (NODE_ENV === "production" && (!SESSION_SECRET || SESSION_SECRET.length < 32)) {
  console.error("Production requires SESSION_SECRET with at least 32 characters.");
  process.exit(1);
}
if (NODE_ENV === "production" && (!ADMIN_EMAIL || ADMIN_PASSWORD.length < 16)) {
  console.error("Production requires ADMIN_EMAIL and ADMIN_PASSWORD (16+ characters).");
  process.exit(1);
}

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "yemen_crypto.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// Safe schema migration for databases created by phase 2.
const userColumns = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!userColumns.includes("role")) db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
if (!userColumns.includes("status")) db.exec("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'");
const auditColumns = db.prepare("PRAGMA table_info(audit_events)").all().map(c => c.name);
if (!auditColumns.includes("details")) db.exec("ALTER TABLE audit_events ADD COLUMN details TEXT");

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: NODE_ENV === "production" ? [] : null
    }
  }
}));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
  name: "yc.sid",
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir, concurrentDB: true }),
  secret: SESSION_SECRET || crypto.randomBytes(48).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-7", legacyHeaders: false, message: { error: "محاولات كثيرة. حاول مرة أخرى بعد قليل." } });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: "draft-7", legacyHeaders: false });
app.use("/api", apiLimiter);
app.use("/api/auth", authLimiter);
app.use(express.static(path.join(__dirname, "public")));

function cleanText(v, max = 100) { return String(v || "").trim().slice(0, max); }
function normalizeEmail(v) { return cleanText(v, 254).toLowerCase(); }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254; }
function csrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  return req.session.csrfToken;
}
function requireCsrf(req, res, next) {
  const sent = String(req.get("x-csrf-token") || req.body?._csrf || "");
  const expected = String(req.session.csrfToken || "");
  const a = Buffer.from(sent), b = Buffer.from(expected);
  if (!a.length || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ error: "انتهت صلاحية الطلب. حدّث الصفحة وحاول مجددًا." });
  }
  next();
}
function publicUser(row) { return { id: row.id, name: row.display_name, email: row.email, role: row.role, status: row.status, createdAt: row.created_at }; }
function logEvent(userId, type, details = null) {
  db.prepare("INSERT INTO audit_events (user_id, event_type, details) VALUES (?, ?, ?)").run(userId || null, type, details);
}
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "سجّل الدخول أولًا." });
  const user = db.prepare("SELECT id, role, status FROM users WHERE id = ?").get(req.session.userId);
  if (!user || user.status !== "active") {
    req.session.destroy(() => {});
    return res.status(403).json({ error: "الحساب غير متاح." });
  }
  req.currentUser = user;
  next();
}
function requireAdmin(req, res, next) {
  requireLogin(req, res, () => {
    if (req.currentUser.role !== "admin") return res.status(403).json({ error: "هذه الصفحة مخصصة للمدير." });
    next();
  });
}

app.get("/api/health", (_req, res) => res.json({ ok: true, mode: "demo", realMoneyEnabled: false }));
app.get("/api/config", (_req, res) => res.json({ localAdminSetupEnabled: NODE_ENV !== "production", realMoneyEnabled: false }));
app.get("/api/auth/csrf", (req, res) => res.json({ csrfToken: csrfToken(req) }));
app.get("/api/auth/me", (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const row = db.prepare("SELECT id,email,display_name,role,status,created_at FROM users WHERE id=?").get(req.session.userId);
  if (!row || row.status !== "active") {
    req.session.destroy(() => {});
    return res.json({ user: null });
  }
  res.json({ user: publicUser(row) });
});

app.post("/api/auth/register", requireCsrf, async (req, res) => {
  const name = cleanText(req.body.name, 80);
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  if (name.length < 2) return res.status(400).json({ error: "الاسم يجب أن يتكون من حرفين على الأقل." });
  if (!validEmail(email)) return res.status(400).json({ error: "أدخل بريدًا إلكترونيًا صحيحًا." });
  if (password.length < 12 || password.length > 128 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: "كلمة المرور يجب أن تكون 12 حرفًا على الأقل وتحتوي على حرف إنجليزي ورقم." });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)").run(email, name, hash);
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "تعذر بدء جلسة الدخول." });
      req.session.userId = Number(result.lastInsertRowid);
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      logEvent(req.session.userId, "register");
      req.session.save(saveErr => {
        if (saveErr) return res.status(500).json({ error: "تم إنشاء الحساب لكن تعذر بدء الجلسة." });
        const row = db.prepare("SELECT id,email,display_name,role,status,created_at FROM users WHERE id=?").get(req.session.userId);
        res.status(201).json({ user: publicUser(row), csrfToken: req.session.csrfToken });
      });
    });
  } catch (e) {
    if (String(e.code || "").startsWith("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "هذا البريد مسجل بالفعل." });
    console.error("Register error:", e.message);
    res.status(500).json({ error: "حدث خطأ داخلي. حاول لاحقًا." });
  }
});

app.post("/api/auth/login", requireCsrf, async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  const row = db.prepare("SELECT id,email,display_name,password_hash,role,status,created_at FROM users WHERE email=?").get(email);
  const valid = row ? await bcrypt.compare(password, row.password_hash) : false;
  if (!valid || row.status !== "active") {
    logEvent(null, "login_failed");
    return res.status(401).json({ error: "البريد الإلكتروني أو كلمة المرور غير صحيحة." });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "تعذر بدء جلسة الدخول." });
    req.session.userId = row.id;
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    logEvent(row.id, "login");
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: "تعذر حفظ جلسة الدخول." });
      res.json({ user: publicUser(row), csrfToken: req.session.csrfToken });
    });
  });
});
app.post("/api/auth/logout", requireCsrf, (req, res) => {
  if (req.session.userId) logEvent(req.session.userId, "logout");
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: "تعذر تسجيل الخروج." });
    res.clearCookie("yc.sid", { httpOnly: true, sameSite: "lax", secure: NODE_ENV === "production" });
    res.json({ ok: true });
  });
});

// Admin bootstrap: one-time local setup using environment variables. No public signup for admin.
app.post("/api/setup-admin", authLimiter, async (req, res) => {
  if (NODE_ENV === "production") return res.status(404).json({ error: "غير متاح." });
  const token = String(req.body.setupToken || "");
  const expected = String(process.env.ADMIN_SETUP_TOKEN || "");
  if (!expected || token !== expected) return res.status(403).json({ error: "رمز إعداد المدير غير صحيح." });
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  const name = cleanText(req.body.name || "مدير يمن كريبتو", 80);
  if (!validEmail(email) || password.length < 16) return res.status(400).json({ error: "استخدم بريدًا صحيحًا وكلمة مرور من 16 حرفًا على الأقل." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const oldAdmin = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
    if (oldAdmin) return res.status(409).json({ error: "يوجد مدير بالفعل. لا يمكن إنشاء مدير آخر من هذه الواجهة." });
    const result = db.prepare("INSERT INTO users (email,display_name,password_hash,role) VALUES (?,?,?,'admin')").run(email, name, hash);
    logEvent(Number(result.lastInsertRowid), "admin_created");
    res.status(201).json({ ok: true, message: "تم إنشاء حساب المدير. سجّل الدخول من الصفحة الرئيسية." });
  } catch (e) {
    if (String(e.code || "").startsWith("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "البريد مسجل بالفعل." });
    console.error("Admin setup error:", e.message);
    res.status(500).json({ error: "تعذر إنشاء حساب المدير." });
  }
});

app.get("/api/admin/summary", requireAdmin, (_req, res) => {
  const users = db.prepare("SELECT COUNT(*) AS total FROM users WHERE role='user'").get().total;
  const active = db.prepare("SELECT COUNT(*) AS total FROM users WHERE role='user' AND status='active'").get().total;
  const suspended = db.prepare("SELECT COUNT(*) AS total FROM users WHERE role='user' AND status='suspended'").get().total;
  const recent = db.prepare("SELECT id,email,display_name,role,status,created_at FROM users ORDER BY id DESC LIMIT 8").all().map(publicUser);
  const events = db.prepare(`
    SELECT a.id,a.event_type,a.details,a.created_at,u.email
    FROM audit_events a LEFT JOIN users u ON u.id=a.user_id
    ORDER BY a.id DESC LIMIT 12
  `).all();
  res.json({ stats: { users, active, suspended }, recent, events, realMoneyEnabled: false });
});
app.get("/api/admin/users", requireAdmin, (req, res) => {
  const q = cleanText(req.query.q, 100);
  const rows = q
    ? db.prepare("SELECT id,email,display_name,role,status,created_at FROM users WHERE role='user' AND (email LIKE ? OR display_name LIKE ?) ORDER BY id DESC LIMIT 100").all(`%${q}%`, `%${q}%`)
    : db.prepare("SELECT id,email,display_name,role,status,created_at FROM users WHERE role='user' ORDER BY id DESC LIMIT 100").all();
  res.json({ users: rows.map(publicUser) });
});
app.post("/api/admin/users/:id/status", requireAdmin, requireCsrf, (req, res) => {
  const id = Number(req.params.id);
  const status = req.body.status;
  if (!Number.isSafeInteger(id) || id < 1 || !["active", "suspended"].includes(status)) {
    return res.status(400).json({ error: "طلب غير صحيح." });
  }
  const result = db.prepare("UPDATE users SET status=? WHERE id=? AND role='user'").run(status, id);
  if (!result.changes) return res.status(404).json({ error: "لم يتم العثور على المستخدم." });
  logEvent(req.session.userId, "admin_user_status", JSON.stringify({ targetUserId: id, status }));
  res.json({ ok: true, message: status === "suspended" ? "تم إيقاف الحساب." : "تم تفعيل الحساب." });
});

// Demo endpoints only; no real payments, wallets, custody, or trading.
app.get("/api/funding-methods", (_req, res) => res.json({
  mode: "demo", realMoneyEnabled: false,
  methods: ["بطاقة Visa / Mastercard (غير مفعّلة)", "محفظة جيب (غير مفعّلة)", "بنك الكريمي (غير مفعّل)"]
}));
app.post("/api/trade-preview", requireLogin, requireCsrf, (req, res) => {
  const pair = cleanText(req.body.pair, 20);
  const side = req.body.side === "sell" ? "sell" : "buy";
  const amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) return res.status(400).json({ error: "أدخل كمية صحيحة للعرض التجريبي." });
  res.json({ mode: "preview", realMoneyEnabled: false, pair, side, amount, message: "معاينة فقط؛ لم يتم تنفيذ أي تداول." });
});

app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

async function bootstrapProductionAdmin() {
  if (NODE_ENV !== "production") return;
  // Admin credentials are supplied by the hosting environment, never by a public signup form.
  const existingAdmin = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
  if (existingAdmin) {
    console.log("Production admin already exists; startup will not change its credentials.");
    return;
  }
  const email = normalizeEmail(ADMIN_EMAIL);
  if (!validEmail(email) || ADMIN_PASSWORD.length < 16) {
    throw new Error("ADMIN_EMAIL must be valid and ADMIN_PASSWORD must be at least 16 characters.");
  }
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  const existingUser = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  let adminId;
  if (existingUser) {
    // The operator explicitly configured this exact email as the production admin.
    db.prepare("UPDATE users SET role='admin', password_hash=?, status='active' WHERE id=?").run(hash, existingUser.id);
    adminId = existingUser.id;
  } else {
    const result = db.prepare("INSERT INTO users (email, display_name, password_hash, role) VALUES (?, ?, ?, 'admin')")
      .run(email, "مدير يمن كريبتو", hash);
    adminId = Number(result.lastInsertRowid);
  }
  logEvent(adminId, "production_admin_bootstrapped");
  console.log("Production admin account is ready for the configured ADMIN_EMAIL.");
}

bootstrapProductionAdmin()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => console.log(`Yemen Crypto demo listening on port ${PORT}`));
  })
  .catch((err) => {
    console.error("Startup failed:", err.message);
    process.exit(1);
  });
