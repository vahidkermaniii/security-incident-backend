// backend/src/modules/auth_module.js
import { Router } from "express";
import jwt from "jsonwebtoken";
import { pool } from "../config/db.js";
import { auth as authRequired } from "../middleware/auth.js";
import { comparePassword, hashPassword } from "../utils/hash.js";

const router = Router();

/* ----------------------------- CONFIG ----------------------------- */
const PASSWORD_MAX_AGE_DAYS = Number(process.env.PASSWORD_MAX_AGE_DAYS || 90); // 0 = غیرفعال

/* ----------------------------- MODEL ------------------------------ */
async function dbGetUserByUsername(username) {
  const [rows] = await pool.query(
    `SELECT id, username, fullname, position, role, status,
            password AS password, password_changed_at
     FROM users WHERE username = ? LIMIT 1`,
    [username]
  );
  return rows?.[0] || null;
}
async function dbGetUserById(id) {
  const [rows] = await pool.query(
    `SELECT id, username, fullname, position, role, status,
            password AS password, password_changed_at
     FROM users WHERE id = ? LIMIT 1`,
    [id]
  );
  return rows?.[0] || null;
}
function buildUserPayload(u) {
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    fullname: u.fullname || "",
    position: u.position || "",
    status: u.status || "active",
  };
}

/* --------------------------- PASSWORD AGE -------------------------- */
function isPasswordExpired(user) {
  try {
    if (!PASSWORD_MAX_AGE_DAYS || PASSWORD_MAX_AGE_DAYS <= 0) return false;
    const ts = user?.password_changed_at;
    // اگر هرگز تغییر داده نشده باشد، از created_at اگر دارید استفاده کنید، وگرنه منقضی فرض کن
    const base = ts ? new Date(ts) : null;
    if (!base || isNaN(base.getTime())) return true;
    const now = new Date();
    const diffMs = now - base;
    const diffDays = diffMs / (1000 * 60 * 60 * 24);
    return diffDays > PASSWORD_MAX_AGE_DAYS;
  } catch {
    return false;
  }
}

/* ------------------------------ TOKENS ------------------------------ */
const ACCESS_SECRET =
  process.env.JWT_ACCESS_SECRET ||
  process.env.JWT_SECRET ||
  process.env.ACCESS_SECRET ||
  "dev_access_secret_change_me";

const REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET ||
  process.env.REFRESH_SECRET ||
  "dev_refresh_secret_change_me";

/** سازگاری با نام‌های مختلف env */
function readExp(namePrimary, nameCompat, fallback) {
  return process.env[namePrimary] || process.env[nameCompat] || fallback;
}
const ACCESS_EXPIRES  = readExp("JWT_ACCESS_EXPIRES",  "JWT_ACCESS_TTL",  "30m");
const REFRESH_EXPIRES = readExp("JWT_REFRESH_EXPIRES", "JWT_REFRESH_TTL", "30m");

const signAccess  = (payload) => jwt.sign(payload, ACCESS_SECRET,  { expiresIn: ACCESS_EXPIRES });
const signRefresh = (payload) => jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });

/* ------------------------------ ROUTES ------------------------------ */

// POST /api/auth/login
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ ok: false, message: "نام کاربری و گذرواژه الزامی است." });
    }

    const user = await dbGetUserByUsername(String(username).trim());
    if (!user || !user.password) {
      return res.status(401).json({ ok: false, message: "نام کاربری یا گذرواژه اشتباه است." });
    }

    const ok = await comparePassword(String(password), user.password);
    if (!ok) {
      return res.status(401).json({ ok: false, message: "نام کاربری یا گذرواژه اشتباه است." });
    }

    if (user.status && user.status !== "active") {
      return res.status(403).json({ ok: false, message: "حساب غیرفعال است." });
    }

    // اگر رمز منقضی شده، اجازه ورود نده
    if (isPasswordExpired(user)) {
      return res.status(403).json({
        ok: false,
        code: "PASSWORD_EXPIRED",
        message: "رمز شما منقضی شده است. لطفاً ابتدا رمز را تغییر دهید."
      });
    }

    const payload = buildUserPayload(user);
    const accessToken  = signAccess(payload);
    const refreshToken = signRefresh({ id: user.id });

    res.json({ ok: true, accessToken, refreshToken, user: payload });
  } catch (e) {
    console.error("AUTH_LOGIN_ERR:", e);
    res.status(500).json({ ok: false, message: "خطا در ورود." });
  }
});

// GET /api/auth/me
router.get("/me", authRequired, async (req, res) => {
  try {
    const me = await dbGetUserById(req.user.id);
    if (!me) return res.status(404).json({ ok: false, message: "کاربر یافت نشد." });
    res.json({ ok: true, user: buildUserPayload(me) });
  } catch (e) {
    console.error("AUTH_ME_ERR:", e);
    res.status(500).json({ ok: false, message: "خطا در دریافت اطلاعات کاربر." });
  }
});

// PATCH /api/auth/password  (برای کاربر لاگین‌شده)
router.patch("/password", authRequired, async (req, res) => {
  try {
    const id = req.user?.id;
    const { current_password, new_password } = req.body || {};
    if (!id) return res.status(401).json({ ok: false, message: "ابتدا وارد شوید." });
    if (!current_password || !new_password) {
      return res.status(400).json({ ok: false, message: "هر دو فیلد رمز فعلی و رمز جدید الزامی هستند." });
    }

    // پیچیدگی رمز
    const pass = String(new_password);
    const okLen = pass.length >= 8;
    const okUpper = /[A-Zآ-ی]/.test(pass);
    const okLower = /[a-z]/.test(pass) || /[اآبپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]/.test(pass);
    const okDigit = /\d/.test(pass);
    const okSpec  = /[^A-Za-z0-9آ-ی]/.test(pass);
    if (!(okLen && okUpper && okLower && okDigit && okSpec)) {
      return res.status(400).json({ ok: false, message: "رمز جدید باید حداقل ۸ کاراکتر و شامل حروف بزرگ/کوچک، عدد و نشانه باشد." });
    }

    const user = await dbGetUserById(id);
    if (!user) return res.status(404).json({ ok: false, message: "کاربر یافت نشد." });

    const ok = await comparePassword(String(current_password), user.password);
    if (!ok) return res.status(400).json({ ok: false, message: "رمز فعلی نادرست است." });

    const hashed = await hashPassword(pass);
    await pool.query("UPDATE users SET password=?, password_changed_at=NOW() WHERE id=?", [hashed, id]);

    res.json({ ok: true, success: true, message: "رمز شما با موفقیت تغییر کرد." });
  } catch (e) {
    console.error("AUTH_CHANGE_PASSWORD_ERR:", e);
    res.status(500).json({ ok: false, message: "خطا در تغییر رمز." });
  }
});

/* --- جدید: تغییر رمز برای حالت منقضی‌شده، بدون نیاز به توکن --- */
// POST /api/auth/password/expired-change
router.post("/password/expired-change", async (req, res) => {
  try {
    const { username, current_password, new_password } = req.body || {};
    if (!username || !current_password || !new_password) {
      return res.status(400).json({ ok: false, message: "نام کاربری، رمز فعلی و رمز جدید الزامی است." });
    }
    const user = await dbGetUserByUsername(String(username).trim());
    if (!user || !user.password) {
      return res.status(404).json({ ok: false, message: "کاربر یافت نشد." });
    }
    if (user.status && user.status !== "active") {
      return res.status(403).json({ ok: false, message: "حساب غیرفعال است." });
    }
    // فقط اجازه بده اگر واقعاً منقضی است (یا می‌خواهی همیشه اجازه بدهی؛ این امن‌تر است)
    if (!isPasswordExpired(user)) {
      return res.status(400).json({ ok: false, message: "رمز عبور منقضی نیست. لطفاً وارد شوید." });
    }

    const ok = await comparePassword(String(current_password), user.password);
    if (!ok) return res.status(400).json({ ok: false, message: "رمز فعلی نادرست است." });

    // پیچیدگی رمز
    const pass = String(new_password);
    const okLen = pass.length >= 8;
    const okUpper = /[A-Zآ-ی]/.test(pass);
    const okLower = /[a-z]/.test(pass) || /[اآبپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]/.test(pass);
    const okDigit = /\d/.test(pass);
    const okSpec  = /[^A-Za-z0-9آ-ی]/.test(pass);
    if (!(okLen && okUpper && okLower && okDigit && okSpec)) {
      return res.status(400).json({ ok: false, message: "رمز جدید باید حداقل ۸ کاراکتر و شامل حروف بزرگ/کوچک، عدد و نشانه باشد." });
    }

    const hashed = await hashPassword(pass);
    await pool.query("UPDATE users SET password=?, password_changed_at=NOW() WHERE id=?", [hashed, user.id]);

    res.json({ ok: true, success: true, message: "رمز با موفقیت تغییر کرد. اکنون وارد شوید." });
  } catch (e) {
    console.error("AUTH_EXPIRED_CHANGE_ERR:", e);
    res.status(500).json({ ok: false, message: "خطا در تغییر رمز." });
  }
});

export default router;
