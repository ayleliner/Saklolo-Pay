require("dotenv").config();
const express = require("express"),
  mysql = require("mysql2/promise"),
  bcrypt = require("bcryptjs"),
  jwt = require("jsonwebtoken"),
  helmet = require("helmet"),
  rl = require("express-rate-limit"),
  C = require("crypto");
const E = process.env,
  B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
  PH = /^09\d{9}$/;
for (const k of ["JWT_SECRET", "VOUCHER_SECRET", "DATA_KEY", "DB_USER"])
  if (!E[k]) throw Error("Missing " + k + " in .env");
const KEY = C.createHash("sha256").update(E.DATA_KEY).digest(),
  db = mysql.createPool({
    host: E.DB_HOST || "localhost",
    user: E.DB_USER,
    password: E.DB_PASS,
    database: E.DB_NAME || "saklolo",
    connectionLimit: 10,
  });
// --- Data Privacy Act: PII encrypted at rest (AES-256-GCM); phone_hash (HMAC) is the lookup key
const enc = (s) => {
  const iv = C.randomBytes(12),
    c = C.createCipheriv("aes-256-gcm", KEY, iv),
    d = Buffer.concat([c.update(String(s), "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), d]).toString("base64");
};
const dec = (b) => {
  const x = Buffer.from(b, "base64"),
    d = C.createDecipheriv("aes-256-gcm", KEY, x.subarray(0, 12));
  d.setAuthTag(x.subarray(12, 28));
  return Buffer.concat([d.update(x.subarray(28)), d.final()]).toString("utf8");
};
const ph = (p) => C.createHmac("sha256", KEY).update(String(p)).digest("hex"),
  sha = (s) => C.createHash("sha256").update(s).digest("hex"),
  mask = (p) => p.slice(0, 4) + "***" + p.slice(-3);
// --- Voucher code: SP-<id>-<amount>-<6-char HMAC tag>; same algorithm runs offline on merchant phones
const tag = (id, v) => {
  const s = C.createHmac("sha256", E.VOUCHER_SECRET)
    .update(id + "|" + v)
    .digest();
  return (
    [...s.subarray(0, 5)].map((b) => B32[b % 32]).join("") + B32[s[5] % 32]
  );
};
const rid = () => [...C.randomBytes(5)].map((b) => B32[b % 32]).join("");
async function tx(f) {
  const c = await db.getConnection();
  try {
    await c.beginTransaction();
    const r = await f(c);
    await c.commit();
    return r;
  } catch (e) {
    await c.rollback();
    throw e;
  } finally {
    c.release();
  }
}
// --- Hash-chained audit ledger (append-only; each row hashes the previous one)
async function led(c, ev, o) {
  const [[l]] = await c.query(
      "SELECT n,hash FROM ledger ORDER BY n DESC LIMIT 1 FOR UPDATE",
    ),
    n = l ? l.n + 1 : 0,
    t = Date.now(),
    d = JSON.stringify(o),
    prev = l ? l.hash : "GENESIS";
  await c.query("INSERT INTO ledger VALUES(?,?,?,?,?,?)", [
    n,
    t,
    ev,
    d,
    prev,
    sha(prev + n + "|" + t + "|" + ev + "|" + d),
  ]);
}
const getCap = async (c) =>
  +(await c.query("SELECT v FROM settings WHERE k='cap'"))[0][0].v;
const answer = async (c, id, yes) => {
  await c.query(
    "UPDATE vouchers SET status=? WHERE id=? AND status='redeemed'",
    [yes ? "confirmed" : "disputed", id],
  );
  await led(c, yes ? "CONFIRM" : "DISPUTE", { id });
};
// --- SMS outbox: rows are queued inside DB transactions, sent after commit (Semaphore), retried up to 5x
const sms = (c, to, text, cid = null) =>
  c.query(
    "INSERT INTO sms_log(to_hash,to_enc,text,confirm_id,t) VALUES(?,?,?,?,?)",
    [ph(to), enc(to), text, cid, Date.now()],
  );
async function flush() {
  const [rows] = await db.query(
    "SELECT id,to_enc,text FROM sms_log WHERE sent=0 AND tries<5 LIMIT 100",
  );
  for (const m of rows) {
    try {
      if (E.SMS_MODE === "live") {
        const p = {
          apikey: E.SEMAPHORE_API_KEY,
          number: dec(m.to_enc),
          message: m.text,
        };
        if (E.SEMAPHORE_SENDER) p.sendername = E.SEMAPHORE_SENDER;
        const r = await fetch("https://api.semaphore.co/api/v4/messages", {
          method: "POST",
          body: new URLSearchParams(p),
        });
        if (!r.ok) throw Error("HTTP " + r.status);
      }
      await db.query("UPDATE sms_log SET sent=1 WHERE id=?", [m.id]);
    } catch (e) {
      console.error("SMS", m.id, e.message);
      await db.query("UPDATE sms_log SET tries=tries+1 WHERE id=?", [m.id]);
    }
  }
}

const app = express();
app.set("trust proxy", 1);
app.use(
  helmet({ contentSecurityPolicy: false }),
  express.json({ limit: "200kb" }),
  express.urlencoded({ extended: false }),
);
const auth =
  (...rs) =>
  (q, r, n) => {
    try {
      q.u = jwt.verify((q.headers.authorization || "").slice(7), E.JWT_SECRET);
      if (rs.length && !rs.includes(q.u.role)) return r.sendStatus(403);
      n();
    } catch (e) {
      r.sendStatus(401);
    }
  };
const W = (f) => (q, r) =>
  f(q, r).catch((e) => {
    console.error(e);
    r.status(500).json({ error: "Server error" });
  });
const lim = rl({ windowMs: 15 * 60e3, max: 60 }),
  bad = (r, m, c = 400) => r.status(c).json({ error: m });

app.post(
  "/api/register",
  lim,
  W(async (q, r) => {
    const { name, phone, brgy, members, pw } = q.body,
      h = ph(phone);
    if (!PH.test(phone) || !name || !pw || pw.length < 6)
      return bad(
        r,
        "Enter your name, an 11-digit 09 number and a password of 6+ characters",
      );
    if (
      (await db.query("SELECT id FROM users WHERE phone_hash=?", [h]))[0].length
    )
      return bad(r, "Number already registered", 409);
    await tx(async (c) => {
      if (
        !(await c.query("SELECT id FROM households WHERE phone_hash=?", [h]))[0]
          .length
      )
        await c.query(
          "INSERT INTO households(phone_hash,phone_enc,name_enc,brgy,members) VALUES(?,?,?,?,?)",
          [h, enc(phone), enc(name), brgy || "", +members || 1],
        );
      await c.query(
        "INSERT INTO users(phone_hash,role,pw_hash,brgy) VALUES(?,?,?,?)",
        [h, "household", await bcrypt.hash(pw, 10), brgy || ""],
      );
      await led(c, "REGISTER", { h: h.slice(0, 12) });
    });
    r.json({ ok: 1 });
  }),
);

app.post(
  "/api/login",
  lim,
  W(async (q, r) => {
    const phone = String(q.body.phone || ""),
      h = ph(phone),
      [[u]] = await db.query("SELECT * FROM users WHERE phone_hash=?", [h]);
    if (!u || !(await bcrypt.compare(String(q.body.pw || ""), u.pw_hash)))
      return bad(r, "Invalid number or password", 401);
    let name = u.name;
    if (u.role === "household")
      name = dec(
        (
          await db.query("SELECT name_enc FROM households WHERE phone_hash=?", [
            h,
          ])
        )[0][0].name_enc,
      );
    r.json({
      token: jwt.sign(
        { id: u.id, role: u.role, name, brgy: u.brgy, h },
        E.JWT_SECRET,
        { expiresIn: "30d" },
      ),
      user: { id: u.id, role: u.role, name, brgy: u.brgy, phone },
    });
  }),
);

app.get(
  "/api/state",
  auth(),
  W(async (q, r) => {
    const u = q.u,
      S = { cap: await getCap(db) };
    S.prices = (await db.query("SELECT item,cap FROM prices"))[0].map((p) => ({
      item: p.item,
      cap: +p.cap,
    }));
    if (u.role === "merchant") S.key = E.VOUCHER_SECRET;
    if (u.role === "household") {
      const phone = dec(
        (
          await db.query(
            "SELECT phone_enc FROM households WHERE phone_hash=?",
            [u.h],
          )
        )[0][0].phone_enc,
      );
      S.vouchers = (
        await db.query(
          "SELECT id,code,val,status FROM vouchers WHERE hh_hash=? ORDER BY issued_at DESC",
          [u.h],
        )
      )[0].map((v) => ({ ...v, phone }));
      S.sms = (
        await db.query(
          "SELECT s.text,s.t,IF(v.status='redeemed',s.confirm_id,NULL) confirm FROM sms_log s LEFT JOIN vouchers v ON v.id=s.confirm_id WHERE s.to_hash=? ORDER BY s.id DESC LIMIT 30",
          [u.h],
        )
      )[0]
        .reverse()
        .map((s) => ({ ...s, to: phone }));
    }
    if (u.role === "admin") {
      S.hh = (
        await db.query("SELECT phone_enc,name_enc,brgy,members FROM households")
      )[0].map((h) => ({
        name: dec(h.name_enc),
        phone: mask(dec(h.phone_enc)),
        brgy: h.brgy,
        members: h.members,
      }));
      S.vouchers = (
        await db.query("SELECT id,val,status,brgy FROM vouchers")
      )[0];
      S.tx = (
        await db.query(
          "SELECT t.n,t.voucher_id vid,t.val,u.name merchant,t.brgy,t.t,t.paid FROM tx t JOIN users u ON u.id=t.merchant_id",
        )
      )[0];
      S.sms = (
        await db.query(
          "SELECT to_enc,text,t FROM sms_log ORDER BY id DESC LIMIT 10",
        )
      )[0]
        .reverse()
        .map((s) => ({ to: mask(dec(s.to_enc)), text: s.text, t: s.t }));
      S.ledger = (
        await db.query("SELECT n,ev,hash FROM ledger ORDER BY n DESC LIMIT 20")
      )[0].reverse();
      S.payouts = (
        await db.query(
          "SELECT u.name merchant,p.amt,p.ch,p.eta FROM payouts p JOIN users u ON u.id=p.merchant_id ORDER BY p.id DESC LIMIT 30",
        )
      )[0];
      S.merchants = (
        await db.query(
          "SELECT name,brgy,wallet FROM users WHERE role='merchant'",
        )
      )[0];
    }
    r.json(S);
  }),
);

app.post(
  "/api/confirm",
  auth("household"),
  W(async (q, r) => {
    await tx(async (c) => {
      const [[v]] = await c.query(
        "SELECT id FROM vouchers WHERE id=? AND hh_hash=? FOR UPDATE",
        [String(q.body.id), q.u.h],
      );
      if (v) await answer(c, v.id, !!q.body.yes);
    });
    r.json({ ok: 1 });
  }),
);
// Two-way SMS: point your gateway's inbound webhook here  ->  POST /api/sms/inbound?token=INBOUND_TOKEN  {from,text}
app.post(
  "/api/sms/inbound",
  W(async (q, r) => {
    if (!E.INBOUND_TOKEN || q.query.token !== E.INBOUND_TOKEN)
      return r.sendStatus(403);
    const t = String(q.body.text || ""),
      yes = /^\s*y/i.test(t),
      no = /^\s*n/i.test(t),
      f =
        "0" +
        String(q.body.from || "")
          .replace(/\D/g, "")
          .slice(-10);
    if (!yes && !no) return r.json({ ok: 0 });
    const id = await tx(async (c) => {
      const [[v]] = await c.query(
        "SELECT id FROM vouchers WHERE hh_hash=? AND status='redeemed' ORDER BY issued_at DESC LIMIT 1 FOR UPDATE",
        [ph(f)],
      );
      if (v) await answer(c, v.id, yes);
      return v && v.id;
    });
    r.json({ ok: !!id });
  }),
);

// --- Merchant sync: authoritative validation, duplicate (palakasan) and per-merchant cap enforcement
app.post(
  "/api/sync",
  auth("merchant"),
  W(async (q, r) => {
    const results = [],
      day = new Date().setHours(0, 0, 0, 0);
    for (const it of (q.body.queue || []).slice(0, 200)) {
      const code = String(it.code || "").toUpperCase(),
        m = code.match(/^SP-([0-9A-Z]{5})-(\d{1,5})-([0-9A-Z]{6})$/);
      let why = null;
      if (!m || tag(m[1], m[2]) !== m[3]) why = "forged";
      else
        why = await tx(async (c) => {
          const [[v]] = await c.query(
            "SELECT * FROM vouchers WHERE id=? FOR UPDATE",
            [m[1]],
          );
          if (!v || v.val !== +m[2]) return "unknown";
          if (v.status !== "issued") {
            const [[t]] = await c.query(
              "SELECT merchant_id FROM tx WHERE voucher_id=?",
              [v.id],
            );
            return t && t.merchant_id === q.u.id ? null : "duplicate";
          }
          const [[s]] = await c.query(
            "SELECT COALESCE(SUM(val),0) s FROM tx WHERE merchant_id=? AND t>=?",
            [q.u.id, day],
          );
          if (+s.s + v.val > (await getCap(c))) return "cap";
          await c.query("UPDATE vouchers SET status='redeemed' WHERE id=?", [
            v.id,
          ]);
          await c.query(
            "INSERT INTO tx(voucher_id,val,merchant_id,brgy,t) VALUES(?,?,?,?,?)",
            [v.id, v.val, q.u.id, q.u.brgy, Date.now()],
          );
          const to = dec(
            (
              await c.query(
                "SELECT phone_enc FROM households WHERE phone_hash=?",
                [v.hh_hash],
              )
            )[0][0].phone_enc,
          );
          await sms(
            c,
            to,
            `SAKLOLO-PAY: PHP${v.val} redeemed at ${q.u.name}. Reply YES to confirm or NO to dispute.`,
            v.id,
          );
          await led(c, "REDEEM", { id: v.id, m: q.u.id });
          return null;
        });
      results.push({ code, why });
    }
    flush().catch(() => {});
    r.json({ results });
  }),
);

// --- Admin
const A = auth("admin");
app.post(
  "/api/admin/households",
  A,
  W(async (q, r) => {
    const { name, phone, brgy } = q.body;
    if (!PH.test(phone) || !name)
      return bad(r, "Name and 09XXXXXXXXX number required");
    await tx(async (c) => {
      await c.query(
        "INSERT IGNORE INTO households(phone_hash,phone_enc,name_enc,brgy) VALUES(?,?,?,?)",
        [ph(phone), enc(phone), enc(name), brgy || ""],
      );
      await led(c, "PREREG", { h: ph(phone).slice(0, 12) });
    });
    r.json({ ok: 1 });
  }),
);
app.post(
  "/api/admin/merchants",
  A,
  W(async (q, r) => {
    const { name, phone, brgy, wallet, pw } = q.body;
    if (!PH.test(phone) || !name || !pw || pw.length < 6)
      return bad(r, "Name, 09 number and 6+ char password required");
    if (
      (
        await db.query("SELECT id FROM users WHERE phone_hash=?", [ph(phone)])
      )[0].length
    )
      return bad(r, "Number already registered", 409);
    await tx(async (c) => {
      await c.query(
        "INSERT INTO users(phone_hash,role,pw_hash,name,brgy,wallet) VALUES(?,?,?,?,?,?)",
        [
          ph(phone),
          "merchant",
          await bcrypt.hash(pw, 10),
          name,
          brgy || "",
          wallet || "GCash",
        ],
      );
      await led(c, "ACCREDIT", { name });
    });
    r.json({ ok: 1 });
  }),
);
app.post(
  "/api/admin/prices",
  A,
  W(async (q, r) => {
    const ps = (q.body.prices || []).filter((p) => p.item && p.cap >= 0),
      cap = Math.round(+q.body.cap);
    if (!(cap > 0)) return bad(r, "Invalid cap");
    await tx(async (c) => {
      await c.query("DELETE FROM prices");
      for (const p of ps)
        await c.query("INSERT INTO prices VALUES(?,?)", [p.item, +p.cap]);
      await c.query("UPDATE settings SET v=? WHERE k='cap'", [cap]);
      await led(c, "POLICY", { ps, cap });
    });
    r.json({ ok: 1 });
  }),
);
app.post(
  "/api/admin/dispatch",
  A,
  W(async (q, r) => {
    const val = Math.round(+q.body.val);
    if (!(val > 0 && val <= 10000)) return bad(r, "Value must be PHP 1-10,000");
    const n = await tx(async (c) => {
      const [hh] = await c.query(
        "SELECT * FROM households h WHERE NOT EXISTS(SELECT 1 FROM vouchers v WHERE v.hh_hash=h.phone_hash AND v.status='issued')",
      );
      for (const h of hh) {
        const id = rid(),
          code = `SP-${id}-${val}-${tag(id, val)}`;
        await c.query(
          "INSERT INTO vouchers(id,code,val,hh_hash,brgy,issued_at) VALUES(?,?,?,?,?,?)",
          [id, code, val, h.phone_hash, h.brgy, Date.now()],
        );
        await sms(
          c,
          dec(h.phone_enc),
          `SAKLOLO-PAY: Relief voucher PHP${val}. Code: ${code}. Show to any accredited store. One-time use. Do not share.`,
        );
        await led(c, "ISSUE", { id, val });
      }
      return hh.length;
    });
    flush().catch(() => {});
    r.json({ n, mode: E.SMS_MODE || "dry" });
  }),
);
app.post(
  "/api/admin/settle",
  A,
  W(async (q, r) => {
    r.json(
      await tx(async (c) => {
        const [rows] = await c.query(
            "SELECT t.n,t.voucher_id,t.val,t.brgy,t.t,t.merchant_id,u.name mn,u.wallet FROM tx t JOIN vouchers v ON v.id=t.voucher_id JOIN users u ON u.id=t.merchant_id WHERE t.paid=0 AND v.status<>'disputed' FOR UPDATE",
          ),
          by = {},
          q = (s) => `"${String(s || "").replace(/"/g, '""')}"`;
        let csv = "ledger_no,voucher,merchant,barangay,amount_php,time\n";
        for (const x of rows) {
          const m = (by[x.merchant_id] = by[x.merchant_id] || {
            amt: 0,
            ch: x.wallet || "GCash",
          });
          m.amt += x.val;
          csv += `${x.n},${x.voucher_id},${q(x.mn)},${q(x.brgy)},${x.val},${new Date(x.t).toISOString()}\n`;
        }
        for (const [id, m] of Object.entries(by)) {
          /* TODO: call your PayMongo/Xendit/GCash disbursement API here, then set status='sent' */ await c.query(
            "INSERT INTO payouts(merchant_id,amt,ch,eta) VALUES(?,?,?,?)",
            [id, m.amt, m.ch, Date.now() + 36 * 36e5],
          );
          await led(c, "PAYOUT", { m: +id, amt: m.amt });
        }
        if (rows.length)
          await c.query("UPDATE tx SET paid=1 WHERE n IN (?)", [
            rows.map((x) => x.n),
          ]);
        return { csv, payouts: Object.keys(by).length };
      }),
    );
  }),
);
app.get(
  "/api/admin/verify",
  A,
  W(async (q, r) => {
    let p = "GENESIS",
      at = null;
    for (const l of (await db.query("SELECT * FROM ledger ORDER BY n"))[0]) {
      if (
        l.prev !== p ||
        l.hash !== sha(p + l.n + "|" + l.t + "|" + l.ev + "|" + l.d)
      ) {
        at = l.n;
        break;
      }
      p = l.hash;
    }
    r.json({ ok: at === null, at });
  }),
);

app.use(express.static("public"));
(async () => {
  const [[a]] = await db.query(
    "SELECT id FROM users WHERE role='admin' LIMIT 1",
  );
  if (!a && E.ADMIN_PHONE && E.ADMIN_PASSWORD) {
    await db.query(
      "INSERT INTO users(phone_hash,role,pw_hash,name) VALUES(?,?,?,?)",
      [
        ph(E.ADMIN_PHONE),
        "admin",
        await bcrypt.hash(E.ADMIN_PASSWORD, 10),
        "LDRRMO Admin",
      ],
    );
    console.log("Admin created:", E.ADMIN_PHONE);
  }
  app.listen(E.PORT || 3000, () =>
    console.log(
      "Saklolo-Pay on :" +
        (E.PORT || 3000) +
        " | SMS mode: " +
        (E.SMS_MODE || "dry"),
    ),
  );
  setInterval(() => flush().catch(() => {}), 15000);
})().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
