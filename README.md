# Saklolo-Pay (Node.js + MySQL + installable phone PWA)
1. Install Node 18+ and MySQL 8 (or MariaDB 10.6+). `mysql -u root -p < schema.sql`, then create a DB user with rights on `saklolo`.
2. `cp .env.example .env` and fill in DB credentials plus the three secrets. Set ADMIN_PHONE / ADMIN_PASSWORD.
3. `npm install && npm start`  (first start creates the admin account).
4. Open the site on a phone over **HTTPS** (needed for "Add to Home Screen", the service worker and the QR camera). Use Caddy or Nginx + Let's Encrypt, or a host such as Render/Railway/a VPS.
5. Log in as admin, open **Merchants** to accredit stores, then residents can self-register. Dispatch sends vouchers.

**SMS:** `SMS_MODE=dry` only logs messages. For real sending set `SMS_MODE=live`, `SEMAPHORE_API_KEY` (and an approved `SEMAPHORE_SENDER`). YES/NO replies work in-app; for replies by SMS, configure your gateway's inbound webhook to `POST /api/sms/inbound?token=INBOUND_TOKEN`.
**Offline:** merchants open the app once online (it caches the shell, ceilings and verification key). After that they can validate and queue sales with no signal; the queue syncs on reconnect.
**Not included yet:** real payout API (stub in `/api/admin/settle`), phone-ownership OTP at registration, per-merchant keys/key rotation, tightened CSP.
