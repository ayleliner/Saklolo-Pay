// Saklolo-Pay v4 server module: resident verification queue, admin-sent vouchers, merchant "apply as redeemer".
// Loaded from the end of server.js. Its routes are registered last, then moved in front of the older ones.
module.exports = (app, X) => {
  const {
      db,
      tx,
      led,
      sms,
      flush,
      ph,
      enc,
      dec,
      tag,
      auth,
      W,
      bad,
      E,
      rid,
      PH,
      mask,
      bcrypt,
      lim,
      MIG,
    } = X,
    A = auth("admin"),
    st = app._router.stack,
    n0 = st.length;
  (MIG || []).push(
    "CREATE TABLE IF NOT EXISTS applications(merchant_id INT PRIMARY KEY,owner VARCHAR(120),email_enc TEXT,phone_enc TEXT,region VARCHAR(80),muni VARCHAR(100),psgc VARCHAR(12),permit VARCHAR(60),area VARCHAR(120),lat DOUBLE NULL,lng DOUBLE NULL,committed_at BIGINT NULL,t BIGINT,status VARCHAR(10) DEFAULT 'draft',note VARCHAR(120))",
    "ALTER TABLE households ADD COLUMN status VARCHAR(10) DEFAULT 'verified'",
    "ALTER TABLE households ADD COLUMN created_at BIGINT NULL",
    "ALTER TABLE households ADD COLUMN note VARCHAR(120) NULL",
    "ALTER TABLE users ADD COLUMN merchant_status VARCHAR(10) DEFAULT 'approved'",
  );
  const s = (x, n = 60) =>
    String(x || "")
      .trim()
      .slice(0, n);
  // ---- extra data on /api/state (the older handler still runs; we add fields to its response)
  async function aug(u, S) {
    if (u.role === "household") {
      const [[h]] = await db.query(
        "SELECT status,note FROM households WHERE phone_hash=?",
        [u.h],
      );
      S.acct = h || { status: "verified" };
    }
    if (u.role === "merchant") {
      const [[m]] = await db.query(
          "SELECT merchant_status s FROM users WHERE id=?",
          [u.id],
        ),
        [[a]] = await db.query(
          "SELECT * FROM applications WHERE merchant_id=?",
          [u.id],
        );
      S.mst = m.s;
      if (m.s !== "approved") delete S.key;
      S.app = {
        store: u.name,
        brgy: u.brgy,
        ...(a
          ? { permit: a.permit, area: a.area, lat: a.lat, note: a.note }
          : {}),
      };
    }
    if (u.role === "admin") {
      const rows = (
          await db.query(
            "SELECT id,phone_hash,phone_enc,name_enc,brgy,region,members,created_at,status FROM households ORDER BY created_at DESC",
          )
        )[0],
        vs = {};
      (
        await db.query("SELECT hh_hash,status FROM vouchers ORDER BY issued_at")
      )[0].forEach((v) => (vs[v.hh_hash] = v.status));
      S.hh = rows.map((h) => ({
        id: h.id,
        name: dec(h.name_enc),
        phone: mask(dec(h.phone_enc)),
        brgy: h.brgy,
        region: h.region,
        members: h.members,
        t: h.created_at,
        status: h.status,
        vs: vs[h.phone_hash] || null,
      }));
      S.pending = S.hh.filter((h) => h.status === "pending");
      S.verified = S.hh.filter((h) => h.status === "verified");
      S.apps = (
        await db.query(
          "SELECT a.merchant_id id,u.name store,u.brgy,a.owner,a.permit,a.area,a.lat,a.lng,a.t FROM applications a JOIN users u ON u.id=a.merchant_id WHERE a.status='pending' ORDER BY a.t",
        )
      )[0];
      S.merchants = (
        await db.query(
          "SELECT id,name,brgy,wallet,suspended FROM users WHERE role='merchant' AND merchant_status='approved'",
        )
      )[0];
    }
  }
  app.get("/api/state", auth(), (q, r, n) => {
    const oj = r.json.bind(r);
    r.json = (S) => {
      aug(q.u, S)
        .catch((e) => console.error("state+", e.message))
        .then(() => oj(S));
    };
    n();
  });

  // ---- registration: residents wait for admin verification; merchants get an account but cannot redeem until approved
  app.post(
    "/api/register",
    lim,
    W(async (q, r) => {
      const b = q.body,
        merchant = b.role === "merchant",
        phone = String(b.phone || "").replace(/\s/g, ""),
        h = ph(phone),
        name = [s(b.first), s(b.middle), s(b.last), s(b.suffix)]
          .filter(Boolean)
          .join(" "),
        email = s(b.email).toLowerCase(),
        store = s(b.store);
      if (
        !PH.test(phone) ||
        !s(b.first) ||
        !s(b.last) ||
        !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ||
        !s(b.region) ||
        !s(b.muni) ||
        !s(b.brgy) ||
        !s(b.psgc) ||
        String(b.pw || "").length < 6 ||
        !b.consent ||
        (merchant && !store)
      )
        return bad(
          r,
          "Please complete every required field and accept the privacy consent",
        );
      if (
        (await db.query("SELECT id FROM users WHERE phone_hash=?", [h]))[0]
          .length
      )
        return bad(r, "Number already registered", 409);
      const addr = (s(b.brgy) + ", " + s(b.muni)).slice(0, 80),
        pw = await bcrypt.hash(String(b.pw), 10);
      await tx(async (c) => {
        if (merchant) {
          const [x] = await c.query(
            "INSERT INTO users(phone_hash,role,pw_hash,name,brgy,wallet,suspended,merchant_status) VALUES(?,?,?,?,?,?,1,'draft')",
            [h, "merchant", pw, store, addr, "GCash"],
          );
          await c.query(
            "INSERT INTO applications(merchant_id,owner,email_enc,phone_enc,region,muni,psgc,t,status) VALUES(?,?,?,?,?,?,?,?,'draft')",
            [
              x.insertId,
              name,
              enc(email),
              enc(phone),
              s(b.region),
              s(b.muni),
              s(b.psgc, 12),
              Date.now(),
            ],
          );
          await led(c, "REG-MERCHANT", { h: h.slice(0, 12), consent: 1 });
        } else {
          await c.query(
            "INSERT INTO households(phone_hash,phone_enc,name_enc,brgy,members,email_enc,region,muni,psgc,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,'pending',?) ON DUPLICATE KEY UPDATE email_enc=VALUES(email_enc),region=VALUES(region),muni=VALUES(muni),psgc=VALUES(psgc)",
            [
              h,
              enc(phone),
              enc(name),
              addr,
              Math.min(30, Math.max(1, +b.members || 1)),
              enc(email),
              s(b.region),
              s(b.muni),
              s(b.psgc, 12),
              Date.now(),
            ],
          );
          await c.query(
            "INSERT INTO users(phone_hash,role,pw_hash,brgy) VALUES(?,?,?,?)",
            [h, "household", pw, addr],
          );
          await led(c, "REGISTER", { h: h.slice(0, 12), consent: 1 });
        }
      });
      r.json({ ok: 1 });
    }),
  );

  // ---- admin: verify or reject a resident
  app.post(
    "/api/admin/verify",
    A,
    W(async (q, r) => {
      const ok = !!q.body.ok,
        id = +q.body.id;
      await tx(async (c) => {
        const [[h]] = await c.query(
          "SELECT phone_enc FROM households WHERE id=? AND status='pending' FOR UPDATE",
          [id],
        );
        if (!h) return;
        await c.query("UPDATE households SET status=?,note=? WHERE id=?", [
          ok ? "verified" : "rejected",
          s(q.body.note, 120),
          id,
        ]);
        await sms(
          c,
          dec(h.phone_enc),
          ok
            ? "SAKLOLO-PAY: Your registration is verified. Your voucher will be sent by SMS and shown in the app when relief distribution opens."
            : "SAKLOLO-PAY: Your registration was not approved. Please contact your barangay or the LDRRMO.",
        );
        await led(c, ok ? "VERIFY" : "REJECT", { hh: id });
      });
      flush().catch(() => {});
      r.json({ ok: 1 });
    }),
  );

  // ---- admin: send vouchers (QR + code in the app, and by SMS) to verified residents only
  const issue = async (q, r, ids) => {
    const val = Math.round(+q.body.val);
    if (!(val > 0 && val <= 10000)) return bad(r, "Value must be PHP 1-10,000");
    const n = await tx(async (c) => {
      const [hh] = await c.query(
        "SELECT * FROM households h WHERE h.status='verified'" +
          (ids.length ? " AND h.id IN (?)" : "") +
          " AND NOT EXISTS(SELECT 1 FROM vouchers v WHERE v.hh_hash=h.phone_hash AND v.status='issued')",
        ids.length ? [ids] : [],
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
  };
  app.post(
    "/api/admin/send-voucher",
    A,
    W((q, r) =>
      issue(
        q,
        r,
        (Array.isArray(q.body.ids) ? q.body.ids : [])
          .map(Number)
          .filter(Boolean),
      ),
    ),
  );
  app.post(
    "/api/admin/dispatch",
    A,
    W((q, r) => issue(q, r, [])),
  );

  // ---- merchant: apply as redeemer (with commitment), admin approves or rejects
  app.post(
    "/api/merchant/apply",
    auth("merchant"),
    W(async (q, r) => {
      const b = q.body,
        ll = (x) =>
          x === null || x === undefined || x === "" || !isFinite(+x)
            ? null
            : +x,
        lat = ll(b.lat),
        lng = ll(b.lng);
      if (!b.commit) return bad(r, "Please accept the commitment");
      if (lat !== null && (Math.abs(lat) > 90 || Math.abs(lng) > 180))
        return bad(r, "Bad coordinates");
      await tx(async (c) => {
        const [x] = await c.query(
          "UPDATE applications SET permit=?,area=?,lat=COALESCE(?,lat),lng=COALESCE(?,lng),committed_at=?,t=?,status='pending',note=NULL WHERE merchant_id=?",
          [
            s(b.permit),
            s(b.area, 120),
            lat,
            lng,
            Date.now(),
            Date.now(),
            q.u.id,
          ],
        );
        if (!x.affectedRows) throw Error("No application record");
        await c.query(
          "UPDATE users SET merchant_status='pending',lat=COALESCE(?,lat),lng=COALESCE(?,lng) WHERE id=? AND merchant_status<>'approved'",
          [lat, lng, q.u.id],
        );
        await led(c, "APPLY", { m: q.u.id });
      });
      r.json({ ok: 1 });
    }),
  );
  app.post(
    "/api/admin/app-review",
    A,
    W(async (q, r) => {
      const ok = !!q.body.ok,
        id = +q.body.id;
      await tx(async (c) => {
        const [[a]] = await c.query(
          "SELECT phone_enc FROM applications WHERE merchant_id=? AND status='pending' FOR UPDATE",
          [id],
        );
        if (!a) return;
        await c.query(
          "UPDATE applications SET status=?,note=? WHERE merchant_id=?",
          [ok ? "approved" : "rejected", s(q.body.note, 120), id],
        );
        await c.query(
          "UPDATE users SET merchant_status=?,suspended=? WHERE id=?",
          [ok ? "approved" : "rejected", ok ? 0 : 1, id],
        );
        if (a.phone_enc)
          await sms(
            c,
            dec(a.phone_enc),
            ok
              ? "SAKLOLO-PAY: Your shop is approved as a voucher redeemer. You can now accept vouchers."
              : "SAKLOLO-PAY: Your redeemer application was not approved. Open the app for details.",
          );
        await led(c, ok ? "APPROVE" : "DECLINE", { m: id });
      });
      flush().catch(() => {});
      r.json({ ok: 1 });
    }),
  );
  // reinstating must never bypass verification
  app.post(
    "/api/admin/suspend",
    A,
    W(async (q, r) => {
      const id = +q.body.id,
        on = q.body.on ? 1 : 0;
      await tx(async (c) => {
        const [[m]] = await c.query(
          "SELECT merchant_status s FROM users WHERE id=? AND role='merchant'",
          [id],
        );
        if (!m || (!on && m.s !== "approved")) return;
        await c.query("UPDATE users SET suspended=? WHERE id=?", [on, id]);
        if (!on)
          await c.query(
            "UPDATE violations SET status='closed' WHERE merchant_id=?",
            [id],
          );
        await led(c, on ? "SUSPEND" : "REINSTATE", { m: id });
      });
      r.json({ ok: 1 });
    }),
  );

  // "Login as X" only accepts an X account (residents are role 'household')
  app.post("/api/login", (q, r, n) => {
    const oj = r.json.bind(r),
      want = q.body.as === "resident" ? "household" : q.body.as,
      name = { household: "Resident", merchant: "Merchant", admin: "Admin" };
    r.json = (j) =>
      want && j && j.user && j.user.role !== want
        ? r
            .status(403)
            .json({
              error: `This is a ${name[j.user.role]} account. Tap "${name[j.user.role]}" above to log in.`,
            })
        : oj(j);
    n();
  });
  const mine = st.splice(n0),
    i = st.findIndex((l) => l.route);
  st.splice(i < 0 ? st.length : i, 0, ...mine);
};
