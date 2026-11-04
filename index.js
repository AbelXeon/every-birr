import "dotenv/config";
import express from "express";
import cors from "cors";
import pg from "pg";

const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5,
});

await pool.query(`
  CREATE TABLE IF NOT EXISTS accounts (
    device_id text, bank text, balance numeric, updated bigint,
    PRIMARY KEY (device_id, bank)
  );
  CREATE TABLE IF NOT EXISTS transactions (
    device_id text, id text, bank text, amount numeric, income boolean,
    category text, note text, ts bigint,
    PRIMARY KEY (device_id, id)
  );
`);

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const auth = (req, res, next) =>
    req.get("x-api-key") === process.env.API_KEY ? next() : res.status(401).json({ error: "unauthorized" });

app.get("/health", (_, res) => res.json({ ok: true }));

app.post("/sync", auth, async(req, res) => {
    const { deviceId, accounts = [], tx = [] } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
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
        console.error(e);
        res.status(500).json({ error: "db error" });
    } finally {
        c.release();
    }
});

app.get("/data/:deviceId", auth, async(req, res) => {
    const a = await pool.query("SELECT * FROM accounts WHERE device_id=$1", [req.params.deviceId]);
    const t = await pool.query("SELECT * FROM transactions WHERE device_id=$1 ORDER BY ts DESC", [req.params.deviceId]);
    res.json({ accounts: a.rows, transactions: t.rows });
});

app.listen(process.env.PORT || 3000, () => console.log("EveryBirr API running"));