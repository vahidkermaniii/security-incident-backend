// backend/src/modules/actions_module.js
import { Router } from "express";
import { auth as authRequired, allowRoles } from "../middleware/auth.js";
import { pool } from "../config/db.js";
import jalaali from "jalaali-js";

const router = Router();

/* ------------------------------- DATE HELPERS ------------------------------ */
const pad2 = (n) => (n < 10 ? `0${n}` : String(n));

function toGregorianISO(jalaliDate) {
  if (!jalaliDate) return null;
  const m = String(jalaliDate).match(/^(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})$/);
  if (!m) return null;
  const { gy, gm, gd } = jalaali.toGregorian(Number(m[1]), Number(m[2]), Number(m[3]));
  return `${gy}-${pad2(gm)}-${pad2(gd)}`;
}

/* ---------------------------------- MODEL --------------------------------- */
const SELECT_BASE = `
  SELECT a.id, a.incident_id, a.description,
         DATE_FORMAT(a.action_date, '%Y-%m-%d') AS action_date,
         a.status_id, s.name AS status_name,
         a.created_by, u.fullname AS admin_fullname,
         DATE_FORMAT(a.created_at, '%Y-%m-%d %H:%i:%s') AS created_at
  FROM actions a
  LEFT JOIN statuses s ON s.id = a.status_id
  LEFT JOIN users u ON u.id = a.created_by
`;

async function dbListByIncident(incidentId) {
  const [rows] = await pool.query(
    SELECT_BASE + " WHERE a.incident_id = ? ORDER BY a.id DESC",
    [incidentId]
  );
  return rows;
}

// شمارش اقدامات یک حادثه
async function dbCountActionsByIncident(incidentId) {
  const [[row]] = await pool.query(
    "SELECT COUNT(*) AS c FROM actions WHERE incident_id = ?",
    [incidentId]
  );
  return Number(row?.c || 0);
}

// ثابت‌های وضعیت مطابق دیتابیس
const CLOSED_STATUS_ID = 4; // 'حل شده'

// اولین اقدام: ست کردن first_action_at اگر هنوز NULL است (با ساعت واقعی)
async function dbMarkFirstActionIfNeeded(incidentId) {
  await pool.query(
    `UPDATE incidents
        SET first_action_at = COALESCE(first_action_at, NOW()),
            updated_at = NOW()
     WHERE id = ?`,
    [incidentId]
  );
}

// اگر وضعیت حل شد: ست کردن resolved_at (در صورت نداشتن مقدار)
async function dbMarkResolvedIfClosed(incidentId, statusId) {
  if (Number(statusId) !== CLOSED_STATUS_ID) return;
  await pool.query(
    `UPDATE incidents
        SET resolved_at = IFNULL(resolved_at, NOW()),
            updated_at = NOW()
      WHERE id = ?`,
    [incidentId]
  );
}

async function dbCreateAction({ incident_id, description, action_date, status_id, created_by }) {
  // سقف ۱۰ اقدام
  const cnt = await dbCountActionsByIncident(incident_id);
  if (cnt >= 10) {
    const err = new Error("برای این حادثه حداکثر ۱۰ اقدام قابل ثبت است.");
    err.status = 409;
    throw err;
  }

  // درج اقدام (اگر تاریخ اقدام ندادی، فقط تاریخ روز ذخیره می‌شود؛ زمان دقیق در created_at است)
  const [ins] = await pool.query(
    `INSERT INTO actions (incident_id, description, action_date, status_id, created_by, added_at, created_at)
     VALUES (?, ?, COALESCE(?, CURDATE()), ?, ?, NOW(), NOW())`,
    [incident_id, description, action_date || null, status_id || null, created_by || null]
  );
  const insertedId = ins.insertId;

  // همگام‌سازی وضعیت Incident
  if (status_id) {
    await pool.query(
      "UPDATE incidents SET status_id = ?, updated_at = NOW() WHERE id = ?",
      [status_id, incident_id]
    );
  }

  // KPI times
  await dbMarkFirstActionIfNeeded(incident_id); // ← با NOW() پر می‌شود اگر خالی بود
  if (status_id) await dbMarkResolvedIfClosed(incident_id, status_id);

  const [rows] = await pool.query(SELECT_BASE + " WHERE a.id = ?", [insertedId]);
  return rows[0];
}

async function dbUpdateAction(id, { description, action_date, status_id }) {
  const sets = [], params = [];
  if (description !== undefined) { sets.push("description = ?"); params.push(description); }
  if (action_date !== undefined) {
    if (action_date === null) { sets.push("action_date = CURDATE()"); }
    else { sets.push("action_date = ?"); params.push(action_date); }
  }
  if (status_id !== undefined) {
    if (status_id === null) { sets.push("status_id = NULL"); }
    else { sets.push("status_id = ?"); params.push(status_id); }
  }

  if (sets.length) {
    params.push(id);
    await pool.query(`UPDATE actions SET ${sets.join(", ")}, updated_at = NOW() WHERE id = ?`, params);

    // اگر status_id تغییر کرد، Incident را هم به‌روزرسانی کن
    if (status_id !== undefined && status_id !== null) {
      const [[r]] = await pool.query("SELECT incident_id FROM actions WHERE id = ? LIMIT 1", [id]);
      const incidentId = r?.incident_id;
      if (incidentId) {
        await pool.query(
          "UPDATE incidents SET status_id = ?, updated_at = NOW() WHERE id = ?",
          [status_id, incidentId]
        );
        await dbMarkResolvedIfClosed(incidentId, status_id);
      }
    }
  }

  const [rows] = await pool.query(SELECT_BASE + " WHERE a.id = ?", [id]);
  return rows[0];
}

async function dbDeleteAction(id) {
  await pool.query("DELETE FROM actions WHERE id=?", [id]);
  return true;
}

async function dbGetIncidentOwnership(incidentId) {
  const [rows] = await pool.query(
    `SELECT id, reporter_id, category_id FROM incidents WHERE id = ? LIMIT 1`,
    [incidentId]
  );
  return rows?.[0] || null;
}

/* ---------------------------------- ACL ----------------------------------- */
function canReadIncident(user, own) {
  if (!user || !own) return false;
  if (user.role === "system-admin") return true;
  if (user.role === "defense-admin") return own.category_id === 2;
  return own.reporter_id === user.id;
}
function canActOnIncident(user, own) {
  if (!user || !own) return false;
  if (user.role === "system-admin") return true;
  if (user.role === "defense-admin") return own.category_id === 2;
  return false;
}

/* --------------------------------- ROUTES --------------------------------- */

// GET /api/actions/:incidentId
router.get("/:incidentId", authRequired, async (req, res) => {
  try {
    const incidentId = Number(req.params.incidentId);
    if (!incidentId) return res.status(400).json({ message: "شناسه حادثه نامعتبر است." });

    const own = await dbGetIncidentOwnership(incidentId);
    if (!own) return res.status(404).json({ message: "حادثه یافت نشد." });
    if (!canReadIncident(req.user, own)) return res.status(403).json({ message: "دسترسی غیرمجاز." });

    const items = await dbListByIncident(incidentId);
    res.json(Array.isArray(items) ? items : []);
  } catch (e) {
    console.error("ACTIONS_LIST_ERR:", e);
    res.status(500).json({ message: "خطا در دریافت اقدامات." });
  }
});

// POST /api/actions
router.post("/", authRequired, allowRoles("defense-admin", "system-admin"), async (req, res) => {
  try {
    const { incident_id, description, action_date_jalali, status_id } = req.body || {};
    const incidentId = Number(incident_id);
    if (!incidentId) return res.status(400).json({ message: "شناسهٔ حادثه نامعتبر است." });
    if (!description || !String(description).trim()) {
      return res.status(400).json({ message: "شرح اقدام الزامی است." });
    }

    const own = await dbGetIncidentOwnership(incidentId);
    if (!own) return res.status(404).json({ message: "حادثه یافت نشد." });
    if (!canActOnIncident(req.user, own)) return res.status(403).json({ message: "اجازه ثبت اقدام ندارید." });

    const iso = action_date_jalali ? toGregorianISO(action_date_jalali) : null;

    const created = await dbCreateAction({
      incident_id: incidentId,
      description: String(description).trim(),
      action_date: iso,
      status_id: status_id ? Number(status_id) : null,
      created_by: req.user?.id || null,
    });
    res.status(201).json(created);
  } catch (e) {
    console.error("ACTIONS_CREATE_ERR:", e);
    res.status(500).json({ message: "ثبت اقدام با خطا مواجه شد." });
  }
});

// PUT /api/actions/:id
router.put("/:id", authRequired, allowRoles("defense-admin", "system-admin"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "شناسه نامعتبر است." });
    const { description, action_date_jalali, status_id } = req.body || {};

    const iso =
      action_date_jalali === undefined
        ? undefined
        : action_date_jalali
        ? toGregorianISO(action_date_jalali)
        : null;

    const updated = await dbUpdateAction(id, {
      description: description !== undefined ? String(description).trim() : undefined,
      action_date: iso,
      status_id: status_id !== undefined ? (status_id ? Number(status_id) : null) : undefined,
    });

    res.json(updated);
  } catch (e) {
    console.error("ACTIONS_UPDATE_ERR:", e);
    res.status(500).json({ message: "ویرایش اقدام با خطا مواجه شد." });
  }
});

// DELETE /api/actions/:id
router.delete("/:id", authRequired, allowRoles("defense-admin", "system-admin"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "شناسه نامعتبر است." });
    await dbDeleteAction(id);
    res.json({ ok: true });
  } catch (e) {
    console.error("ACTIONS_DELETE_ERR:", e);
    res.status(500).json({ message: "حذف اقدام با خطا مواجه شد." });
  }
});

export default router;
