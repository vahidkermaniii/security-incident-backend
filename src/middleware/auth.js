// backend/src/middleware/auth.js
import jwt from "jsonwebtoken";
import { pool } from "../config/db.js";

/* ============== کاندیدهای Secret (سازگار با کد قبلی) ============== */
const CANDIDATE_ACCESS_SECRETS = [
  process.env.JWT_ACCESS_SECRET,
  process.env.JWT_SECRET,
  process.env.ACCESS_SECRET,
  "dev_access_secret_change_me", // فقط برای توسعه؛ در prod ممنوع
].filter(Boolean);

/* ============== ممنوعیت dev_* در Production ============== */
const isProd = process.env.NODE_ENV === "production";
if (isProd && CANDIDATE_ACCESS_SECRETS.some(s => String(s).includes("dev_"))) {
  throw new Error("Refusing to start with dev JWT secret in production.");
}

/* ============== Verify با هر secret موجود ============== */
function verifyWithAnySecret(token) {
  let lastErr = null;
  for (const sec of CANDIDATE_ACCESS_SECRETS) {
    try { return jwt.verify(token, sec); } catch (e) { lastErr = e; }
  }
  if (lastErr) throw lastErr;
  throw new Error("No JWT secret configured.");
}

/* ============== بارگیری اطلاعات کاربر (در صورت نیاز) ============== */
async function hydrateUserIfNeeded(payload) {
  const id = Number(payload?.id || 0);
  if (!id) return payload;
  try {
    const [[row]] = await pool.query(
      "SELECT id, username, fullname, role FROM users WHERE id = ? LIMIT 1",
      [id]
    );
    if (!row) {
      const err = new Error("User not found");
      err.status = 403;
      throw err;
    }
    return { id: row.id, username: row.username, fullname: row.fullname, role: row.role };
  } catch {
    // اگر DB در دسترس نبود، همان payload را برگردان (رفتار قبلی)
    return payload;
  }
}

/* ============== سیاست انقضای رمز (قابل تنظیم) ============== */
const PASSWORD_MAX_AGE_DAYS = Number(process.env.PASSWORD_MAX_AGE_DAYS || 90);

async function checkPasswordExpiry(userId, role) {
  if (String(role).toLowerCase() === "system-admin") return { expired: false };
  const [[row]] = await pool.query(
    "SELECT password_changed_at FROM users WHERE id = ? LIMIT 1",
    [userId]
  );
  const changedAt = row?.password_changed_at ? new Date(row.password_changed_at) : null;
  if (!changedAt) return { expired: true, days: 9999 };

  const diffMs = Date.now() - changedAt.getTime();
  const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  return { expired: days > PASSWORD_MAX_AGE_DAYS, days };
}

/* ============== مسیرهای مجاز هنگام انقضای رمز ============== */
function isExpiredWhitelist(req) {
  const m = (req.method || "GET").toUpperCase();
  const url = String(
    req.originalUrl || (req.baseUrl || "") + (req.path || "") || req.url || ""
  ).toLowerCase();

  if (m === "GET"  && /\/api\/auth\/me$/.test(url))       return true;
  if (m === "PATCH"&& /\/api\/auth\/password$/.test(url)) return true;
  if (m === "POST" && /\/api\/auth\/logout$/.test(url))   return true;
  return false;
}

/* ============== Middleware اصلی ============== */
export async function auth(req, res, next) {
  try {
    const authH = String(req.headers?.authorization || "");
    const token = authH.startsWith("Bearer ") ? authH.slice(7) : null;

    if (!token) {
      return res.status(401).json({ message: "ابتدا باید وارد شوید.", code: "NO_TOKEN" });
    }

    let payload;
    try {
      payload = verifyWithAnySecret(token);
    } catch (e) {
      const isExp = e?.name === "TokenExpiredError";
      return res.status(401).json({
        message: isExp ? "نشست منقضی شده است." : "توکن نامعتبر است.",
        code: isExp ? "EXPIRED_ACCESS" : "INVALID_ACCESS",
      });
    }

    const hydrated = await hydrateUserIfNeeded(payload);
    req.user = {
      id: hydrated.id,
      username: hydrated.username || payload.username || "",
      fullname: hydrated.fullname || payload.fullname || "",
      role: hydrated.role || payload.role || "user",
    };

    const { expired } = await checkPasswordExpiry(req.user.id, req.user.role);
    if (expired && !isExpiredWhitelist(req)) {
      return res.status(403).json({
        message: "رمز شما منقضی شده است. لطفاً ابتدا رمز را تغییر دهید.",
        code: "PASSWORD_EXPIRED",
      });
    }

    return next();
  } catch (e) {
    console.error("AUTH_MIDDLEWARE_ERR:", e);
    return res.status(500).json({ message: "خطا در احراز هویت." });
  }
}

/* ============== کنترل نقش‌ها ============== */
export function allowRoles(...roles) {
  const allowed = roles.map(r => String(r || "").toLowerCase());
  return (req, res, next) => {
    try {
      if (!req.user) return res.status(401).json({ message: "ابتدا باید وارد شوید." });
      const myRole = String(req.user.role || "").toLowerCase();
      if (myRole === "system-admin") return next();
      if (!allowed.includes(myRole)) return res.status(403).json({ message: "دسترسی غیرمجاز." });
      return next();
    } catch (e) {
      console.error("ALLOW_ROLES_ERR:", e);
      return res.status(500).json({ message: "خطای دسترسی." });
    }
  };
}

export default { auth, allowRoles };
