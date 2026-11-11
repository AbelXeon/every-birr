import "dotenv/config";
import crypto from "node:crypto";
import express from "express";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";

const { DATABASE_URL, JWT_SECRET, API_KEY, BREVO_API_KEY, BREVO_SENDER_EMAIL } = process.env;
const BREVO_SENDER_NAME = process.env.BREVO_SENDER_NAME || "EveryBirr";
const DEV_LOG_CODES = process.env.DEV_LOG_CODES === "true"; // local testing only, NEVER set this on Render

if (!DATABASE_URL) throw new Error("DATABASE_URL is missing");
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error("JWT_SECRET is missing or shorter than 32 characters");
if (!DEV_LOG_CODES && (!BREVO_API_KEY || !BREVO_SENDER_EMAIL)) {
    console.warn("WARNING: BREVO_API_KEY or BREVO_SENDER_EMAIL is missing, emails will fail");
}

const pool = new pg.Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5,
});

await pool.query(`
  -- old tables (the installed app still uses these until Phase 3)
  CREATE TABLE IF NOT EXISTS accounts (
    device_id text, bank text, balance numeric, updated bigint,
    PRIMARY KEY (device_id, bank)
  );
  CREATE TABLE IF NOT EXISTS transactions (
    device_id text, id text, bank text, amount numeric, income boolean,
    category text, note text, ts bigint,
    PRIMARY KEY (device_id, id)
  );

  -- new: users and their data
  CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    pin_hash text NOT NULL,
    failed_attempts int NOT NULL DEFAULT 0,
    locked_until timestamptz,
    token_version int NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS email_codes (
    email text NOT NULL,
    purpose text NOT NULL,
    user_id uuid,
    code_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    attempts int NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (email, purpose)
  );
  CREATE TABLE IF NOT EXISTS user_accounts (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bank text NOT NULL, balance numeric NOT NULL, updated bigint NOT NULL,
    PRIMARY KEY (user_id, bank)
  );
  CREATE TABLE IF NOT EXISTS user_transactions (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id text NOT NULL, bank text NOT NULL, amount numeric NOT NULL, income boolean NOT NULL,
    category text, note text, ts bigint NOT NULL,
    PRIMARY KEY (user_id, id)
  );
  CREATE TABLE IF NOT EXISTS user_deleted_accounts (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bank text NOT NULL, deleted_at bigint NOT NULL,
    PRIMARY KEY (user_id, bank)
  );
`);

// ---------------------------------------------------------------- helpers

const EMAIL_RX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const PIN_RX = /^\d{6}$/;
const normEmail = (e) => String(e || "").trim().toLowerCase();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const httpError = (status, code, extra) => Object.assign(new Error(code), { status, code, extra });

const hmac = (s) => crypto.createHmac("sha256", JWT_SECRET).update(s).digest("hex");
const safeEq = (a, b) => {
    const x = Buffer.from(a),
        y = Buffer.from(b);
    return x.length === y.length && crypto.timingSafeEqual(x, y);
};

function weakPin(p) {
    if (/^(\d)\1{5}$/.test(p)) return true; // 111111
    return "0123456789".includes(p) || "9876543210".includes(p); // 123456, 654321
}

function validNewPin(p) {
    if (typeof p !== "string" || !PIN_RX.test(p)) throw httpError(400, "bad_pin_format");
    if (weakPin(p)) throw httpError(400, "weak_pin");
}

// ---- email (Brevo)

let dayKey = "";
let sentToday = 0;

function countEmail() {
    const k = new Date().toISOString().slice(0, 10);
    if (k !== dayKey) { dayKey = k;
        sentToday = 0; }
    if (sentToday >= 250) return false; // Brevo free plan is 300 a day
    sentToday++;
    return true;
}

async function sendEmail(to, code) {
    if (DEV_LOG_CODES) { console.log(`[DEV] code for ${to}: ${code}`); return; }
    if (!countEmail()) throw httpError(503, "email_limit");
    let res;
    try {
        res = await fetch("https://api.brevo.com/v3/smtp/email", {
            method: "POST",
            headers: { "api-key": BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
            body: JSON.stringify({
                sender: { email: BREVO_SENDER_EMAIL, name: BREVO_SENDER_NAME },
                to: [{ email: to }],
                subject: `${code} is your EveryBirr code`,
                textContent: `Your EveryBirr code is ${code}. It expires in 10 minutes. If you did not ask for it, you can ignore this email.`,
                htmlContent: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px">` +
                    `<h2 style="margin:0 0 12px">EveryBirr</h2><p>Your code is</p>` +
                    `<p style="font-size:34px;letter-spacing:8px;font-weight:700;margin:8px 0">${code}</p>` +
                    `<p style="color:#666">It expires in 10 minutes. If you did not ask for it, you can ignore this email.</p></div>`,
            }),
        });
    } catch (e) {
        console.error("Brevo network error:", e.message);
        throw httpError(502, "email_failed");
    }
    if (!res.ok) {
        console.error("Brevo error:", res.status, await res.text());
        throw httpError(502, "email_failed");
    }
}

async function issueCode(email, purpose, userId = null) {
    const { rows } = await pool.query("SELECT created_at FROM email_codes WHERE email=$1 AND purpose=$2", [email, purpose]);
    if (rows[0]) {
        const age = (Date.now() - new Date(rows[0].created_at).getTime()) / 1000;
        if (age < 60) throw httpError(429, "too_soon", { retryAfter: Math.ceil(60 - age) });
    }
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
    await pool.query(
        `INSERT INTO email_codes(email,purpose,user_id,code_hash,expires_at,attempts,created_at)
         VALUES($1,$2,$3,$4, now() + interval '10 minutes', 0, now())
         ON CONFLICT (email,purpose) DO UPDATE
         SET user_id=EXCLUDED.user_id, code_hash=EXCLUDED.code_hash,
             expires_at=EXCLUDED.expires_at, attempts=0, created_at=now()`, [email, purpose, userId, hmac(`${email}|${purpose}|${code}`)]
    );
    try {
        await sendEmail(email, code);
    } catch (e) {
        await pool.query("DELETE FROM email_codes WHERE email=$1 AND purpose=$2", [email, purpose]);
        throw e;
    }
}

async function consumeCode(email, purpose, code) {
    const { rows } = await pool.query(
        "SELECT code_hash, expires_at, attempts, user_id FROM email_codes WHERE email=$1 AND purpose=$2", [email, purpose]
    );
    const r = rows[0];
    if (!r || new Date(r.expires_at) < new Date()) throw httpError(400, "code_expired");
    if (r.attempts >= 5) {
        await pool.query("DELETE FROM email_codes WHERE email=$1 AND purpose=$2", [email, purpose]);
        throw httpError(400, "code_expired");
    }
    const ok = /^\d{6}$/.test(code) && safeEq(r.code_hash, hmac(`${email}|${purpose}|${code}`));
    if (!ok) {
        await pool.query("UPDATE email_codes SET attempts=attempts+1 WHERE email=$1 AND purpose=$2", [email, purpose]);
        throw httpError(400, "code_wrong");
    }
    await pool.query("DELETE FROM email_codes WHERE email=$1 AND purpose=$2", [email, purpose]);
    return r.user_id;
}

// ---- tokens

const accessToken = (u) =>
    jwt.sign({ typ: "access", v: u.token_version }, JWT_SECRET, { subject: u.id, expiresIn: "180d" });
const makeTicket = (email, purpose) =>
    jwt.sign({ typ: "ticket", purpose, email }, JWT_SECRET, { expiresIn: "10m" });

function readTicket(t, purpose) {
    try {
        const p = jwt.verify(String(t || ""), JWT_SECRET, { algorithms: ["HS256"] });
        if (p.typ !== "ticket" || p.purpose !== purpose) throw new Error("wrong ticket");
        return p.email;
    } catch (e) {
        throw httpError(400, "ticket_invalid");
    }
}

async function requireUser(req, res, next) {
    const m = /^Bearer (.+)$/.exec(req.get("authorization") || "");
    if (!m) return res.status(401).json({ error: "unauthorized" });
    try {
        const p = jwt.verify(m[1], JWT_SECRET, { algorithms: ["HS256"] });
        if (p.typ !== "access") throw new Error("wrong token");
        const { rows } = await pool.query("SELECT id,email,token_version FROM users WHERE id=$1", [p.sub]);
        if (!rows[0] || rows[0].token_version !== p.v) return res.status(401).json({ error: "session_expired" });
        req.user = rows[0];
        next();
    } catch (e) {
        res.status(401).json({ error: "unauthorized" });
    }
}

// ---- PIN check with lockout: 5 wrong tries = locked for 15 minutes

const DUMMY_HASH = bcrypt.hashSync("000000", 10);

async function checkPin(user, pin, badCode = "bad_credentials") {
    if (user && user.locked_until && new Date(user.locked_until) > new Date()) {
        throw httpError(429, "locked", { retryAfter: Math.ceil((new Date(user.locked_until) - Date.now()) / 1000) });
    }
    const p = typeof pin === "string" ? pin : "";
    const match = await bcrypt.compare(p, user ? user.pin_hash : DUMMY_HASH); // always runs, same timing
    if (!user) throw httpError(401, badCode);
    if (match && PIN_RX.test(p)) {
        if (user.failed_attempts) {
            await pool.query("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=$1", [user.id]);
        }
        return;
    }
    const n = user.failed_attempts + 1;
    if (n >= 5) {
        await pool.query("UPDATE users SET failed_attempts=0, locked_until=now() + interval '15 minutes' WHERE id=$1", [user.id]);
        throw httpError(429, "locked", { retryAfter: 900 });
    }
    await pool.query("UPDATE users SET failed_attempts=$2 WHERE id=$1", [user.id, n]);
    throw httpError(401, badCode, { attemptsLeft: 5 - n });
}

const getUser = async(id) => (await pool.query("SELECT * FROM users WHERE id=$1", [id])).rows[0];

// ---------------------------------------------------------------- app

const app = express();
app.set("trust proxy", 1); // Render sits behind one proxy
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const lim = { standardHeaders: true, legacyHeaders: false, message: { error: "too_many_requests" } };
const authLimiter = rateLimit({...lim, windowMs: 15 * 60 * 1000, limit: 60 });
const mailLimiter = rateLimit({...lim, windowMs: 60 * 60 * 1000, limit: 10 });
app.use("/auth", authLimiter);

app.get("/health", (_, res) => res.json({ ok: true }));

// latest app version, edited from Render environment variables (public: it is not a secret)
app.get("/version", (_, res) => res.json({
    versionCode: Number(process.env.APP_VERSION_CODE || 2),
    versionName: process.env.APP_VERSION_NAME || "1.1",
    apkUrl: process.env.APP_APK_URL || "",
    notes: process.env.APP_NOTES || ""
}));

// ---- create account: email -> code -> PIN

app.post("/auth/register/request", mailLimiter, wrap(async(req, res) => {
    const email = normEmail(req.body.email);
    if (!EMAIL_RX.test(email)) throw httpError(400, "bad_email");
    const exists = await pool.query("SELECT 1 FROM users WHERE email=$1", [email]);
    if (exists.rowCount) throw httpError(409, "email_exists");
    await issueCode(email, "register");
    res.json({ ok: true });
}));

app.post("/auth/register/check", wrap(async(req, res) => {
    const email = normEmail(req.body.email);
    await consumeCode(email, "register", String(req.body.code || ""));
    res.json({ ticket: makeTicket(email, "register") });
}));

app.post("/auth/register/complete", wrap(async(req, res) => {
    const email = readTicket(req.body.ticket, "register");
    validNewPin(req.body.pin);
    const hash = await bcrypt.hash(req.body.pin, 10);
    let user;
    try {
        const r = await pool.query(
            "INSERT INTO users(email, pin_hash) VALUES($1,$2) RETURNING id,email,token_version", [email, hash]);
        user = r.rows[0];
    } catch (e) {
        if (e.code === "23505") throw httpError(409, "email_exists");
        throw e;
    }
    res.json({ token: accessToken(user), email: user.email });
}));

// ---- login

app.post("/auth/login", wrap(async(req, res) => {
    const email = normEmail(req.body.email);
    const user = (await pool.query("SELECT * FROM users WHERE email=$1", [email])).rows[0];
    await checkPin(user, req.body.pin);
    res.json({ token: accessToken(user), email: user.email });
}));

// ---- forgot PIN

app.post("/auth/reset/request", mailLimiter, wrap(async(req, res) => {
    const email = normEmail(req.body.email);
    if (!EMAIL_RX.test(email)) throw httpError(400, "bad_email");
    const user = (await pool.query("SELECT id FROM users WHERE email=$1", [email])).rows[0];
    if (user) await issueCode(email, "reset", user.id);
    res.json({ ok: true }); // same answer whether the email exists or not
}));

app.post("/auth/reset/check", wrap(async(req, res) => {
    const email = normEmail(req.body.email);
    await consumeCode(email, "reset", String(req.body.code || ""));
    res.json({ ticket: makeTicket(email, "reset") });
}));

app.post("/auth/reset/complete", wrap(async(req, res) => {
    const email = readTicket(req.body.ticket, "reset");
    validNewPin(req.body.pin);
    const hash = await bcrypt.hash(req.body.pin, 10);
    const { rows } = await pool.query(
        `UPDATE users SET pin_hash=$2, token_version=token_version+1, failed_attempts=0, locked_until=NULL
         WHERE email=$1 RETURNING id,email,token_version`, [email, hash]);
    if (!rows[0]) throw httpError(400, "ticket_invalid");
    res.json({ token: accessToken(rows[0]), email: rows[0].email });
}));

// ---- signed-in account actions

app.get("/me", requireUser, (req, res) => res.json({ email: req.user.email }));

app.post("/auth/pin/change", requireUser, wrap(async(req, res) => {
    const u = await getUser(req.user.id);
    await checkPin(u, req.body.currentPin, "bad_pin");
    validNewPin(req.body.newPin);
    const hash = await bcrypt.hash(req.body.newPin, 10);
    const { rows } = await pool.query(
        "UPDATE users SET pin_hash=$2, token_version=token_version+1 WHERE id=$1 RETURNING id,email,token_version", [u.id, hash]);
    res.json({ token: accessToken(rows[0]) }); // other phones must sign in again
}));

app.post("/auth/email/request", mailLimiter, requireUser, wrap(async(req, res) => {
    const u = await getUser(req.user.id);
    await checkPin(u, req.body.pin, "bad_pin");
    const newEmail = normEmail(req.body.newEmail);
    if (!EMAIL_RX.test(newEmail)) throw httpError(400, "bad_email");
    const taken = await pool.query("SELECT 1 FROM users WHERE email=$1", [newEmail]);
    if (taken.rowCount) throw httpError(409, "email_exists");
    await issueCode(newEmail, "change_email", u.id);
    res.json({ ok: true });
}));

app.post("/auth/email/confirm", requireUser, wrap(async(req, res) => {
    const newEmail = normEmail(req.body.newEmail);
    const userId = await consumeCode(newEmail, "change_email", String(req.body.code || ""));
    if (userId !== req.user.id) throw httpError(400, "code_wrong");
    try {
        await pool.query("UPDATE users SET email=$2 WHERE id=$1", [req.user.id, newEmail]);
    } catch (e) {
        if (e.code === "23505") throw httpError(409, "email_exists");
        throw e;
    }
    res.json({ email: newEmail });
}));

app.post("/auth/delete-account", requireUser, wrap(async(req, res) => {
    const u = await getUser(req.user.id);
    await checkPin(u, req.body.pin, "bad_pin");
    await pool.query("DELETE FROM email_codes WHERE user_id=$1", [u.id]);
    await pool.query("DELETE FROM users WHERE id=$1", [u.id]); // data tables delete with it
    res.json({ ok: true });
}));

// ---- per-user data sync

const isNum = (x) => x !== null && x !== "" && Number.isFinite(Number(x));

app.post("/v2/sync", requireUser, wrap(async(req, res) => {
    const accounts = Array.isArray(req.body.accounts) ? req.body.accounts : [];
    const tx = Array.isArray(req.body.tx) ? req.body.tx : [];
    if (accounts.length > 50 || tx.length > 2000) throw httpError(413, "too_much_data");
    for (const a of accounts) {
        if (typeof a.bank !== "string" || a.bank.length > 20 || !isNum(a.balance) || !isNum(a.updated)) throw httpError(400, "bad_data");
    }
    for (const t of tx) {
        if (typeof t.id !== "string" || t.id.length > 64 || typeof t.bank !== "string" || t.bank.length > 20 ||
            !isNum(t.amount) || !isNum(t.ts)) throw httpError(400, "bad_data");
    }

    const uid = req.user.id;
    const c = await pool.connect();
    try {
        await c.query("BEGIN");
        for (const a of accounts) {
            await c.query(
                `INSERT INTO user_accounts(user_id,bank,balance,updated) VALUES($1,$2,$3,$4)
                 ON CONFLICT (user_id,bank) DO UPDATE
                 SET balance=EXCLUDED.balance, updated=EXCLUDED.updated
                 WHERE user_accounts.updated <= EXCLUDED.updated`, [uid, a.bank, a.balance, a.updated]
            );
            // an account created again after being deleted clears its "deleted" mark
            await c.query("DELETE FROM user_deleted_accounts WHERE user_id=$1 AND bank=$2 AND deleted_at < $3", [uid, a.bank, a.updated]);
        }
        const deadRows = (await c.query("SELECT bank, deleted_at FROM user_deleted_accounts WHERE user_id=$1", [uid])).rows;
        const dead = new Map(deadRows.map((r) => [r.bank, Number(r.deleted_at)]));
        for (const t of tx) {
            if (dead.has(t.bank) && dead.get(t.bank) >= Number(t.ts)) continue; // belongs to a deleted account
            await c.query(
                `INSERT INTO user_transactions(user_id,id,bank,amount,income,category,note,ts)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (user_id,id) DO UPDATE SET category=EXCLUDED.category, note=EXCLUDED.note`, [uid, t.id, t.bank, t.amount, !!t.income, t.category || null, t.note || "", t.ts]
            );
        }
        await c.query("COMMIT");
        res.json({ ok: true });
    } catch (e) {
        await c.query("ROLLBACK");
        throw e;
    } finally {
        c.release();
    }
}));

app.get("/v2/pull", requireUser, wrap(async(req, res) => {
    const uid = req.user.id;
    const [a, t, d] = await Promise.all([
        pool.query("SELECT bank,balance,updated FROM user_accounts WHERE user_id=$1", [uid]),
        pool.query("SELECT id,bank,amount,income,category,note,ts FROM user_transactions WHERE user_id=$1 ORDER BY ts DESC LIMIT 5000", [uid]),
        pool.query("SELECT bank,deleted_at FROM user_deleted_accounts WHERE user_id=$1", [uid]),
    ]);
    res.json({
        accounts: a.rows.map((r) => ({ bank: r.bank, balance: Number(r.balance), updated: Number(r.updated) })),
        transactions: t.rows.map((r) => ({
            id: r.id,
            bank: r.bank,
            amount: Number(r.amount),
            income: r.income,
            category: r.category,
            note: r.note || "",
            ts: Number(r.ts),
        })),
        deletedAccounts: d.rows.map((r) => ({ bank: r.bank, deletedAt: Number(r.deleted_at) })),
    });
}));

app.delete("/v2/account/:bank", requireUser, wrap(async(req, res) => {
    const uid = req.user.id;
    const bank = String(req.params.bank).slice(0, 20);
    const c = await pool.connect();
    try {
        await c.query("BEGIN");
        await c.query("DELETE FROM user_transactions WHERE user_id=$1 AND bank=$2", [uid, bank]);
        await c.query("DELETE FROM user_accounts WHERE user_id=$1 AND bank=$2", [uid, bank]);
        await c.query(
            `INSERT INTO user_deleted_accounts(user_id,bank,deleted_at) VALUES($1,$2,$3)
             ON CONFLICT (user_id,bank) DO UPDATE SET deleted_at=EXCLUDED.deleted_at`, [uid, bank, Date.now()]
        );
        await c.query("COMMIT");
        res.json({ ok: true });
    } catch (e) {
        await c.query("ROLLBACK");
        throw e;
    } finally {
        c.release();
    }
}));

// ---------------------------------------------------------------- OLD routes
// The installed app still uses these (shared key). We remove them after Phase 3.

const legacyAuth = (req, res, next) =>
    API_KEY && req.get("x-api-key") === API_KEY ? next() : res.status(401).json({ error: "unauthorized" });

app.post("/sync", legacyAuth, wrap(async(req, res) => {
    const { deviceId, accounts = [], tx = [] } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    console.log(`legacy sync: ${accounts.length} accounts, ${tx.length} transactions`);
    const c = await pool.connect();
    try {
        await c.query("BEGIN");
        for (const a of accounts) {
            await c.query(
                `INSERT INTO accounts(device_id,bank,balance,updated) VALUES($1,$2,$3,$4)
                 ON CONFLICT (device_id,bank) DO UPDATE
                 SET balance=EXCLUDED.balance, updated=EXCLUDED.updated
                 WHERE accounts.updated <= EXCLUDED.updated`, [deviceId, a.bank, a.balance, a.updated]
            );
        }
        for (const t of tx) {
            await c.query(
                `INSERT INTO transactions(device_id,id,bank,amount,income,category,note,ts)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (device_id,id) DO UPDATE SET category=EXCLUDED.category, note=EXCLUDED.note`, [deviceId, t.id, t.bank, t.amount, t.income, t.category, t.note, t.ts]
            );
        }
        await c.query("COMMIT");
        res.json({ ok: true });
    } catch (e) {
        await c.query("ROLLBACK");
        throw e;
    } finally {
        c.release();
    }
}));

app.delete("/account/:deviceId/:bank", legacyAuth, wrap(async(req, res) => {
    const { deviceId, bank } = req.params;
    const c = await pool.connect();
    try {
        await c.query("BEGIN");
        await c.query("DELETE FROM transactions WHERE device_id=$1 AND bank=$2", [deviceId, bank]);
        await c.query("DELETE FROM accounts WHERE device_id=$1 AND bank=$2", [deviceId, bank]);
        await c.query("COMMIT");
        res.json({ ok: true });
    } catch (e) {
        await c.query("ROLLBACK");
        throw e;
    } finally {
        c.release();
    }
}));

app.get("/data/:deviceId", legacyAuth, wrap(async(req, res) => {
    const a = await pool.query("SELECT * FROM accounts WHERE device_id=$1", [req.params.deviceId]);
    const t = await pool.query("SELECT * FROM transactions WHERE device_id=$1 ORDER BY ts DESC", [req.params.deviceId]);
    res.json({ accounts: a.rows, transactions: t.rows });
}));

// ---------------------------------------------------------------- errors

app.use((err, req, res, next) => {
    if (err.status) return res.status(err.status).json(Object.assign({ error: err.code }, err.extra || {}));
    console.error(err);
    res.status(500).json({ error: "server_error" });
});

app.listen(process.env.PORT || 3000, () => console.log("EveryBirr API running"));