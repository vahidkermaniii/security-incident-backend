// backend/src/modules/users.module.js
// ماژول Users: Model + Controller + Routes

import { Router } from "express";
import { auth as authRequired } from "../middleware/auth.js";
import { pool } from "../config/db.js";
import { hashPassword, comparePassword } from "../utils/hash.js";

const router = Router();

/* -------------------------------------------------------------------------- */
/*                               Helpers / Policy                              */
/* -------------------------------------------------------------------------- */
function mapUserRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    fullname: row.fullname,
    position: row.position,
    role: row.role,          // "user" | "defense-admin" | "system-admin"
    status: row.status,      // "active" | "inactive"
    created_at: row.created_at || null,
  };
}

function isSystemAdmin(req) { return req?.user?.role === "system-admin"; }

/** اعتبارسنجی پیچیدگی رمز عبور (سازگار با فارسی) */
function validatePasswordComplexity(pass) {
  const p = String(pass || "");
  if (p.length < 8) return false;
  const hasLetter = /[A-Za-z\u0600-\u06FF]/.test(p);   // هر حرفی: فارسی/لاتین
  const hasDigit  = /\d/.test(p);                      // عدد
  const hasSpec   = /[^A-Za-z0-9\u0600-\u06FF]/.test(p); // نشانه
  return hasLetter && hasDigit && hasSpec;
}

/* -------------------------------------------------------------------------- */
/*                                   MODEL                                    */
/* -------------------------------------------------------------------------- */
async function dbGetUserByUsername(username) {
  const sql = `
    SELECT id, username, fullname, position, role, status,
           password AS password,
           DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at
    FROM users WHERE username = ? LIMIT 1`;
  const [rows] = await pool.query(sql, [username]);
  return rows[0] || null;
}

async function dbGetUserById(id) {
  const sql = `
    SELECT id, username, fullname, position, role, status,
           password AS password,
           DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at
    FROM users WHERE id = ? LIMIT 1`;
  const [rows] = await pool.query(sql, [id]);
  return rows[0] || null;
}

async function dbListUsers({ q, role, status } = {}) {
  const where = [];
  const params = [];
  if (q) { where.push("(username LIKE ? OR fullname LIKE ?)"); params.push(`%${q}%`, `%${q}%`); }
  if (role) { where.push("role = ?"); params.push(role); }
  if (status) { where.push("status = ?"); params.push(status); }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const sql = `
    SELECT id, username, fullname, position, role, status,
           DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at
    FROM users ${whereSql}
    ORDER BY id DESC`;
  const [rows] = await pool.query(sql, params);
  return rows;
}

async function dbCreateUser({ username, passwordHash, fullname, position, role, status = "active" }) {
  const sql = `INSERT INTO users (username, password, fullname, position, role, status, created_at, password_changed_at)
               VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())`;
  const [res] = await pool.query(sql, [username, passwordHash, fullname, position, role, status]);
  return dbGetUserById(res.insertId);
}

async function dbUpdateUser(id, fields = {}) {
  const { username, fullname, position, role, status, passwordHash } = fields;
  const sets = [], vals = [];
  if (username !== undefined) { sets.push("username = ?"); vals.push(username); }
  if (fullname !== undefined) { sets.push("fullname = ?"); vals.push(fullname); }
  if (position !== undefined) { sets.push("position = ?"); vals.push(position); }
  if (role !== undefined) { sets.push("role = ?"); vals.push(role); }
  if (status !== undefined) { sets.push("status = ?"); vals.push(status); }
  if (passwordHash !== undefined) {
    sets.push("password = ?", "password_changed_at = NOW()");
    vals.push(passwordHash);
  }
  if (!sets.length) return dbGetUserById(id);
  const sql = `UPDATE users SET ${sets.join(", ")} WHERE id = ?`;
  vals.push(id);
  await pool.query(sql, vals);
  return dbGetUserById(id);
}

async function dbDeleteUser(id) {
  await pool.query("DELETE FROM users WHERE id = ?", [id]);
  return { ok: true };
}

/* -------------------------------------------------------------------------- */
/*                                 CONTROLLER                                 */
/* -------------------------------------------------------------------------- */

// GET /api/users?q=&role=&status=
router.get("/", authRequired, async (req, res) => {
  try {
    if (!isSystemAdmin(req)) return res.status(403).json({ message: "دسترسی غیرمجاز." });
    const { q, role, status } = req.query || {};
    const rows = await dbListUsers({
      q: q ? String(q).trim() : undefined,
      role: role || undefined,
      status: status || undefined,
    });
    res.json(rows.map(mapUserRow));
  } catch (e) {
    console.error("USERS_LIST_ERR:", e);
    res.status(500).json({ message: "خطا در دریافت فهرست کاربران." });
  }
});

// GET /api/users/:id
router.get("/:id", authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });
    const me = req.user; if (!me) return res.status(401).json({ message: "نیاز به ورود دارید." });
    if (!isSystemAdmin(req) && me.id !== id) return res.status(403).json({ message: "دسترسی غیرمجاز." });
    const user = await dbGetUserById(id);
    if (!user) return res.status(404).json({ message: "کاربر یافت نشد." });
    res.json(mapUserRow(user));
  } catch (e) {
    console.error("USERS_GET_ERR:", e);
    res.status(500).json({ message: "خطا در دریافت کاربر." });
  }
});

// POST /api/users
router.post("/", authRequired, async (req, res) => {
  try {
    if (!isSystemAdmin(req)) return res.status(403).json({ message: "دسترسی غیرمجاز." });
    const { username, fullname, position, role, status, password } = req.body || {};
    if (!username || !fullname || !role || !password) return res.status(400).json({ message: "فیلدهای اجباری ناقص است." });
    if (!["user","defense-admin","system-admin"].includes(role)) return res.status(400).json({ message: "نقش نامعتبر است." });
    if (status && !["active","inactive"].includes(status)) return res.status(400).json({ message: "وضعیت نامعتبر است." });

    const existing = await dbGetUserByUsername(String(username).trim());
    if (existing) return res.status(409).json({ message: "نام کاربری تکراری است." });

    if (!validatePasswordComplexity(password)) {
      return res.status(400).json({ message: "رمز باید حداقل ۸ کاراکتر و شامل حروف بزرگ/کوچک، عدد و نشانه باشد." });
    }

    const passwordHash = await hashPassword(String(password));
    const created = await dbCreateUser({
      username: String(username).trim(),
      fullname: String(fullname).trim(),
      position: position ? String(position).trim() : null,
      role,
      status: status || "active",
      passwordHash,
    });
    res.status(201).json(mapUserRow(created));
  } catch (e) {
    console.error("USERS_CREATE_ERR:", e);
    res.status(500).json({ message: "ایجاد کاربر با خطا مواجه شد." });
  }
});

// PUT /api/users/:id
router.put("/:id", authRequired, async (req, res) => {
  try {
    if (!isSystemAdmin(req)) return res.status(403).json({ message: "دسترسی غیرمجاز." });
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });

    const prev = await dbGetUserById(id); if (!prev) return res.status(404).json({ message: "کاربر یافت نشد." });

    const { username, fullname, position, role, status } = req.body || {};
    const fields = {};
    if (username !== undefined) {
      const u = String(username).trim(); if (!u) return res.status(400).json({ message: "نام کاربری نمی‌تواند خالی باشد." });
      if (u !== prev.username) { const exists = await dbGetUserByUsername(u); if (exists) return res.status(409).json({ message: "نام کاربری تکراری است." }); }
      fields.username = u;
    }
    if (fullname !== undefined) fields.fullname = String(fullname).trim();
    if (position !== undefined) fields.position = position ? String(position).trim() : null;
    if (role !== undefined) {
      if (!["user","defense-admin","system-admin"].includes(role)) return res.status(400).json({ message: "نقش نامعتبر است." });
      fields.role = role;
    }
    if (status !== undefined) {
      if (!["active","inactive"].includes(status)) return res.status(400).json({ message: "وضعیت نامعتبر است." });
      fields.status = status;
    }

    const updated = await dbUpdateUser(id, fields);
    res.json(mapUserRow(updated));
  } catch (e) {
    console.error("USERS_UPDATE_ERR:", e);
    res.status(500).json({ message: "ویرایش کاربر با خطا مواجه شد." });
  }
});

/* ------------------------- Password Change Routes ------------------------- */
/**
 * ترتیب مهم است: اول /me/password سپس /:id/password
 * تا /users/me/password به‌اشتباه به /:id/password نرود و خطای «شناسه نامعتبر» نگیریم.
 */

// PATCH /api/users/me/password  (تغییر رمز توسط خود کاربر با تأیید رمز فعلی)
router.patch("/me/password", authRequired, async (req, res) => {
  try {
    const meId = req.user?.id;
    if (!meId) return res.status(401).json({ message: "نیاز به ورود دارید." });

    const { current_password, new_password } = req.body || {};
    if (!current_password || !new_password) {
      return res.status(400).json({ message: "رمز فعلی و رمز جدید الزامی است." });
    }

    if (!validatePasswordComplexity(new_password)) {
      return res.status(400).json({ message: "رمز جدید باید حداقل ۸ کاراکتر و شامل حروف بزرگ/کوچک، عدد و نشانه باشد." });
    }

    const me = await dbGetUserById(meId);
    if (!me) return res.status(404).json({ message: "کاربر یافت نشد." });

    const ok = await comparePassword(String(current_password), me.password);
    if (!ok) return res.status(400).json({ message: "رمز فعلی نادرست است." });

    const passwordHash = await hashPassword(String(new_password));
    const updated = await dbUpdateUser(meId, { passwordHash });
    res.json({ success: true, user: mapUserRow(updated) });
  } catch (e) {
    console.error("USERS_ME_PASSWORD_ERR:", e);
    res.status(500).json({ message: "تغییر رمز با خطا مواجه شد." });
  }
});

// PATCH /api/users/:id/password  (فقط سیستم‌ادمین برای سایرین)
router.patch("/:id/password", authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!isSystemAdmin(req)) return res.status(403).json({ message: "دسترسی غیرمجاز." });
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });

    const { password } = req.body || {};
    if (!password) return res.status(400).json({ message: "رمز عبور جدید الزامی است." });

    if (!validatePasswordComplexity(password)) {
      return res.status(400).json({ message: "رمز باید حداقل ۸ کاراکتر و شامل حروف بزرگ/کوچک، عدد و نشانه باشد." });
    }

    const prev = await dbGetUserById(id); if (!prev) return res.status(404).json({ message: "کاربر یافت نشد." });
    const passwordHash = await hashPassword(String(password));
    const updated = await dbUpdateUser(id, { passwordHash });
    res.json(mapUserRow(updated));
  } catch (e) {
    console.error("USERS_PASSWORD_ERR:", e);
    res.status(500).json({ message: "تغییر رمز عبور با خطا مواجه شد." });
  }
});

// DELETE /api/users/:id
router.delete("/:id", authRequired, async (req, res) => {
  try {
    if (!isSystemAdmin(req)) return res.status(403).json({ message: "دسترسی غیرمجاز." });
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });
    if (req.user?.id === id) return res.status(400).json({ message: "نمی‌توانید حساب کاربری خود را حذف کنید." });
    await dbDeleteUser(id);
    res.json({ success: true });
  } catch (e) {
    console.error("USERS_DELETE_ERR:", e);
    res.status(500).json({ message: "حذف کاربر با خطا مواجه شد." });
  }
});

export default router;
