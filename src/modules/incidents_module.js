// backend/src/modules/incidents_module.js
import { Router } from "express";
import { auth as authRequired, allowRoles } from "../middleware/auth.js";
import { pool } from "../config/db.js";
import jalaali from "jalaali-js";

const router = Router();

/* ------------------------------- DATE HELPERS ------------------------------ */
// نرمال‌سازی ورودی شمسی (ارقام فارسی/عربی، جداکننده‌ها و فاصله‌ها)
function normalizeJalaliInput(input = "") {
  const fa = "۰۱۲۳۴۵۶۷۸۹";
  const ar = "٠١٢٣٤٥٦٧٨٩";
  let s = String(input).trim();
  s = s.replace(/[۰-۹]/g, d => String(fa.indexOf(d)))
       .replace(/[٠-٩]/g, d => String(ar.indexOf(d)))
       .replace(/[\.\/]/g, "-")
       .replace(/\s+/g, " ");
  return s;
}
const pad2 = (n) => (n < 10 ? `0${n}` : String(n));

/**
 * تبدیل تاریخ شمسی (YYYY-MM-DD) + زمان (HH:mm اختیاری) به رشته‌ی میلادی ISO برای MySQL
 * مثال خروجی: "2025-09-12 07:41:00"
 */
function toGregorianISO(jalaliDate, timeHHmm) {
  if (!jalaliDate) return null;
  const norm = normalizeJalaliInput(jalaliDate);
  const m = String(norm).match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (!m) return null;

  // ✅ تبدیل دقیق با jalaali-js (جلوگیری از جابه‌جایی ~۲۰ روزه)
  const { gy, gm, gd } = jalaali.toGregorian(Number(m[1]), Number(m[2]), Number(m[3]));
  const time =
    timeHHmm && /^\d{1,2}:\d{2}$/.test(String(timeHHmm).trim())
      ? String(timeHHmm).trim()
      : "00:00";
  return `${gy}-${pad2(gm)}-${pad2(gd)} ${time}:00`;
}

/* ---------------------------------- MODEL --------------------------------- */
function categoryLabelById(cid) {
  if (cid === 1) return "cyber";
  if (cid === 2) return "physical";
  return `cat_${cid ?? ""}`;
}

async function dbListMyIncidents(userId) {
  const [rows] = await pool.query(
    `
    SELECT
      i.id, i.title, i.category_id,
      CASE WHEN i.category_id=1 THEN 'cyber'
           WHEN i.category_id=2 THEN 'physical'
           ELSE CONCAT('cat_', i.category_id) END AS category_label,
      i.location_id,  l.name  AS location_name,
      i.priority_id,  p.name  AS priority_name,
      i.status_id,    s.name  AS status_name,
      i.description,
      i.reporter_id,  u.username AS reporter_username, u.fullname AS reporter_fullname,
      DATE_FORMAT(i.submission_date, '%Y-%m-%d %H:%i:%s') AS submission_date,
      DATE_FORMAT(i.created_at,       '%Y-%m-%d %H:%i:%s') AS created_at,
      -- ✅ افزوده‌ها برای داشبورد:
      DATE_FORMAT(i.first_action_at,  '%Y-%m-%d %H:%i:%s') AS first_action_at,
      DATE_FORMAT(i.resolved_at,      '%Y-%m-%d %H:%i:%s') AS resolved_at,

      -- آمار و آخرین اقدام
      ac.actions_count,
      la.description                                                   AS last_action_description,
      DATE_FORMAT(la.action_date, '%Y-%m-%d')                          AS last_action_date,
      DATE_FORMAT(COALESCE(la.added_at, la.created_at), '%Y-%m-%d %H:%i:%s') AS last_action_at,
      la.status_id                                                     AS last_action_status_id,
      ls.name                                                          AS last_action_status_name

    FROM incidents i
    LEFT JOIN locations  l ON l.id = i.location_id
    LEFT JOIN priorities p ON p.id = i.priority_id
    LEFT JOIN statuses   s ON s.id = i.status_id
    LEFT JOIN users      u ON u.id = i.reporter_id

    LEFT JOIN (
      SELECT incident_id,
             COUNT(*) AS actions_count,
             MAX(id)  AS last_action_id
      FROM actions
      GROUP BY incident_id
    ) ac ON ac.incident_id = i.id
    LEFT JOIN actions  la ON la.id = ac.last_action_id
    LEFT JOIN statuses ls ON ls.id = la.status_id

    WHERE i.reporter_id = ?
    ORDER BY i.id DESC
    `,
    [userId]
  );
  return rows;
}

async function dbListAllByFilters(filters = {}) {
  const { status_id, priority_id, location_id, category_id, search, scope, reporter_id } = filters;
  const where = [], params = [];

  if (scope === "physical") where.push("i.category_id = 2");
  if (status_id)   { where.push("i.status_id = ?");   params.push(Number(status_id)); }
  if (priority_id) { where.push("i.priority_id = ?"); params.push(Number(priority_id)); }
  if (location_id) { where.push("i.location_id = ?"); params.push(Number(location_id)); }
  if (category_id) { where.push("i.category_id = ?"); params.push(Number(category_id)); }
  if (reporter_id) { where.push("i.reporter_id = ?"); params.push(Number(reporter_id)); }

  if (search) {
    const s = String(search).slice(0, 256); // جلوگیری از کوئری بسیار طولانی
    where.push("(i.title LIKE ? OR i.description LIKE ?)");
    const like = `%${s}%`;
    params.push(like, like);
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const [rows] = await pool.query(
    `
    SELECT
      i.id, i.title, i.category_id,
      CASE WHEN i.category_id=1 THEN 'cyber'
           WHEN i.category_id=2 THEN 'physical'
           ELSE CONCAT('cat_', i.category_id) END AS category_label,
      i.location_id,  l.name  AS location_name,
      i.priority_id,  p.name  AS priority_name,
      i.status_id,    s.name  AS status_name,
      i.description,
      i.reporter_id,  u.username AS reporter_username, u.fullname AS reporter_fullname,
      DATE_FORMAT(i.submission_date, '%Y-%m-%d %H:%i:%s') AS submission_date,
      DATE_FORMAT(i.created_at,       '%Y-%m-%d %H:%i:%s') AS created_at,
      -- ✅ افزوده‌ها برای داشبورد:
      DATE_FORMAT(i.first_action_at,  '%Y-%m-%d %H:%i:%s') AS first_action_at,
      DATE_FORMAT(i.resolved_at,      '%Y-%m-%d %H:%i:%s') AS resolved_at,

      -- آمار و آخرین اقدام
      ac.actions_count,
      la.description                                                   AS last_action_description,
      DATE_FORMAT(la.action_date, '%Y-%m-%d')                          AS last_action_date,
      DATE_FORMAT(COALESCE(la.added_at, la.created_at), '%Y-%m-%d %H:%i:%s') AS last_action_at,
      la.status_id                                                     AS last_action_status_id,
      ls.name                                                          AS last_action_status_name

    FROM incidents i
    LEFT JOIN locations  l ON l.id = i.location_id
    LEFT JOIN priorities p ON p.id = i.priority_id
    LEFT JOIN statuses   s ON s.id = i.status_id
    LEFT JOIN users      u ON u.id = i.reporter_id

    LEFT JOIN (
      SELECT incident_id,
             COUNT(*) AS actions_count,
             MAX(id)  AS last_action_id
      FROM actions
      GROUP BY incident_id
    ) ac ON ac.incident_id = i.id
    LEFT JOIN actions  la ON la.id = ac.last_action_id
    LEFT JOIN statuses ls ON ls.id = la.status_id

    ${whereSql}
    ORDER BY i.id DESC
    `,
    params
  );
  return rows;
}

async function dbGetIncidentById(id) {
  const [rows] = await pool.query(
    `
    SELECT
      i.id, i.title, i.category_id,
      CASE WHEN i.category_id=1 THEN 'cyber'
           WHEN i.category_id=2 THEN 'physical'
           ELSE CONCAT('cat_', i.category_id) END AS category_label,
      i.location_id,  l.name  AS location_name,
      i.priority_id,  p.name  AS priority_name,
      i.status_id,    s.name  AS status_name,
      i.description,
      i.reporter_id,  u.username AS reporter_username, u.fullname AS reporter_fullname,
      DATE_FORMAT(i.submission_date, '%Y-%m-%d %H:%i:%s') AS submission_date,
      DATE_FORMAT(i.created_at,       '%Y-%m-%d %H:%i:%s') AS created_at,
      DATE_FORMAT(i.first_action_at,  '%Y-%m-%d %H:%i:%s') AS first_action_at,
      DATE_FORMAT(i.resolved_at,      '%Y-%m-%d %H:%i:%s') AS resolved_at,
      DATE_FORMAT(i.updated_at,       '%Y-%m-%d %H:%i:%s') AS updated_at,

      ac.actions_count,
      la.description                                                   AS last_action_description,
      DATE_FORMAT(la.action_date, '%Y-%m-%d')                          AS last_action_date,
      DATE_FORMAT(COALESCE(la.added_at, la.created_at), '%Y-%m-%d %H:%i:%s') AS last_action_at,
      la.status_id                                                     AS last_action_status_id,
      ls.name                                                          AS last_action_status_name

    FROM incidents i
    LEFT JOIN locations  l ON l.id = i.location_id
    LEFT JOIN priorities p ON p.id = i.priority_id
    LEFT JOIN statuses   s ON s.id = i.status_id
    LEFT JOIN users      u ON u.id = i.reporter_id

    LEFT JOIN (
      SELECT incident_id,
             COUNT(*) AS actions_count,
             MAX(id)  AS last_action_id
      FROM actions
      GROUP BY incident_id
    ) ac ON ac.incident_id = i.id
    LEFT JOIN actions  la ON la.id = ac.last_action_id
    LEFT JOIN statuses ls ON ls.id = la.status_id

    WHERE i.id = ?
    LIMIT 1
    `,
    [id]
  );
  return rows?.[0] || null;
}

async function dbCreateIncident(data) {
  const {
    title, description, location_id, priority_id, status_id,
    reporter_id, category_id, submission_date
  } = data;

  const [res] = await pool.query(
    `
    INSERT INTO incidents
      (title, description, location_id, priority_id, status_id, reporter_id, category_id, submission_date, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(?, NOW()), NOW())
    `,
    [
      title,
      description,
      Number(location_id),
      Number(priority_id),
      status_id ? Number(status_id) : null,
      Number(reporter_id),
      Number(category_id),
      submission_date || null,
    ]
  );
  return await dbGetIncidentById(res.insertId);
}

/* ----------------------------------- ACL ---------------------------------- */
function canReadIncident(user, incident) {
  if (!user || !incident) return false;
  const { role, id } = user;
  if (role === "system-admin") return true;
  if (role === "defense-admin") return incident.category_id === 2;
  return incident.reporter_id === id;
}
function isAdmin(user) {
  return user?.role === "system-admin" || user?.role === "defense-admin";
}

/* --------------------------------- ROUTES --------------------------------- */
// GET /api/incidents/mine
router.get("/mine", authRequired, async (req, res) => {
  try {
    const me = req.user;
    const rows = await dbListMyIncidents(me.id);
    res.json(rows);
  } catch (e) {
    console.error("INCIDENTS_MINE_ERR:", e);
    res.status(500).json({ message: "خطا در دریافت گزارش‌های شما." });
  }
});

// GET /api/incidents  (admins list with filters & reporter filter)
router.get(
  "/",
  authRequired,
  allowRoles("defense-admin", "system-admin"),
  async (req, res) => {
    try {
      const { status_id, priority_id, location_id, category_id, search, scope, reporter_id } = req.query || {};

      // اگر نقش defense-admin است، فقط فیزیکال را برگردان
      const forcedScope = req.user?.role === "defense-admin" ? "physical" : (scope === "physical" ? "physical" : "all");
      const forcedCategoryId = req.user?.role === "defense-admin" ? 2 : (category_id || undefined);

      const rows = await dbListAllByFilters({
        status_id: status_id ? Number(status_id) : undefined,
        priority_id: priority_id ? Number(priority_id) : undefined,
        location_id: location_id ? Number(location_id) : undefined,
        category_id: forcedCategoryId ? Number(forcedCategoryId) : undefined,
        reporter_id: reporter_id ? Number(reporter_id) : undefined,
        search: search ? String(search).trim() : undefined,
        scope: forcedScope,
      });
      res.json(rows);
    } catch (e) {
      console.error("INCIDENTS_ALL_ERR:", e);
      res.status(500).json({ message: "خطا در دریافت فهرست حوادث." });
    }
  }
);

// GET /api/incidents/:id
router.get("/:id", authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "شناسه نامعتبر است." });
    const incident = await dbGetIncidentById(id);
    if (!incident) return res.status(404).json({ message: "حادثه یافت نشد." });
    if (!canReadIncident(req.user, incident)) return res.status(403).json({ message: "دسترسی غیرمجاز." });
    res.json(incident);
  } catch (e) {
    console.error("INCIDENTS_GET_ERR:", e);
    res.status(500).json({ message: "خطا در دریافت حادثه." });
  }
});

// POST /api/incidents
router.post("/", authRequired, async (req, res) => {
  try {
    const me = req.user;
    const {
      title_id,         // اگر عنوان از عناوین از پیش‌تعریف شده باشد
      title_text,       // اگر کاربر عنوان دلخواه زده باشد
      description,
      location_id,
      priority_id,      // = درجه ریسک
      category_id,      // 1: cyber, 2: physical
      submission_date_jalali,  // "YYYY-MM-DD" شمسی
      submission_time,         // "HH:mm"
      status_id,        // اختیاری (معمولاً خالی)
    } = req.body || {};

    const title = (title_text && String(title_text).trim())
      || (title_id ? `#${title_id}` : "")
      || "";
    if (!title) return res.status(400).json({ message: "عنوان حادثه الزامی است." });
    if (!description || !String(description).trim()) return res.status(400).json({ message: "شرح حادثه الزامی است." });
    if (!location_id) return res.status(400).json({ message: "محل وقوع را مشخص کنید." });
    if (!priority_id) return res.status(400).json({ message: "درجه ریسک را مشخص کنید." });
    if (!category_id) return res.status(400).json({ message: "دسته‌بندی را مشخص کنید." });

 
    // تبدیل تاریخ شمسی + زمان به میلادی (اگر فرستاده شده باشد)، در غیر این صورت NOW()
    const iso = submission_date_jalali ? toGregorianISO(submission_date_jalali, submission_time) : null;

    const created = await dbCreateIncident({
      title: String(title),
      description: String(description).trim(),
      location_id,
      priority_id,
      status_id: status_id ? Number(status_id) : null,
      reporter_id: me.id,
      category_id,
      submission_date: iso, // اگر null باشد COALESCE -> NOW()
    });

    res.status(201).json(created);
  } catch (e) {
    console.error("INCIDENTS_CREATE_ERR:", e);
    res.status(500).json({ message: "ثبت حادثه با خطا مواجه شد." });
  }
});

export default router;
