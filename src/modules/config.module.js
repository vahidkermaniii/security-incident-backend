// backend/src/modules/config.module.js
import { Router } from "express";
import { auth as authRequired, allowRoles } from "../middleware/auth.js";
import { pool } from "../config/db.js";

const router = Router();

/* ------------------------------- MODEL ----------------------------------- */
function tableNameByType(type) {
  switch (type) {
    case "location":  return "locations";
    case "priority":  return "priorities";
    case "status":    return "statuses";
    case "title":     return "incident_titles";
    default: throw new Error("نوع نامعتبر است.");
  }
}

async function dbGetAllConfig() {
  const [titles]    = await pool.query(`SELECT id AS title_id, title, category_id FROM incident_titles ORDER BY id ASC`);
  const [locations] = await pool.query(`SELECT id, name FROM locations ORDER BY id ASC`);
  const [priorities]= await pool.query(`SELECT id, name FROM priorities ORDER BY id ASC`);
  const [statuses]  = await pool.query(`SELECT id, name FROM statuses  ORDER BY id ASC`);
  return {
    titles: {
      cyber:    titles.filter(t => t.category_id === 1),
      physical: titles.filter(t => t.category_id === 2),
    },
    locations, priorities, statuses,
  };
}
async function dbGetTitlesByCategory(categoryId) {
  const [rows] = await pool.query(
    `SELECT id AS title_id, title FROM incident_titles WHERE category_id = ? ORDER BY id ASC`,
    [categoryId]
  );
  return rows;
}
async function dbAddConfigItem(type, name, category_id) {
  const table = tableNameByType(type);
  if (table === "incident_titles") {
    const cid = Number(category_id) === 2 ? 2 : 1;
    const [res] = await pool.query(
      `INSERT INTO incident_titles (title, category_id) VALUES (?, ?)`,
      [name, cid]
    );
    const [rows] = await pool.query(
      `SELECT id AS title_id, title, category_id FROM incident_titles WHERE id=?`,
      [res.insertId]
    );
    return rows[0];
  } else {
    const [res] = await pool.query(`INSERT INTO ${table} (name) VALUES (?)`, [name]);
    const [rows] = await pool.query(`SELECT id, name FROM ${table} WHERE id=?`, [res.insertId]);
    return rows[0];
  }
}
async function dbUpdateConfigItem(type, id, name) {
  const table = tableNameByType(type);
  if (table === "incident_titles") {
    await pool.query(`UPDATE incident_titles SET title = ? WHERE id = ?`, [name, id]);
    const [rows] = await pool.query(`SELECT id AS title_id, title, category_id FROM incident_titles WHERE id=?`, [id]);
    return rows[0];
  } else {
    await pool.query(`UPDATE ${table} SET name = ? WHERE id = ?`, [name, id]);
    const [rows] = await pool.query(`SELECT id, name FROM ${table} WHERE id=?`, [id]);
    return rows[0];
  }
}
async function dbDeleteConfigItem(type, id) {
  const table = tableNameByType(type);
  await pool.query(`DELETE FROM ${table} WHERE id = ?`, [id]);
  return { ok: true };
}

/* ------------------------------ ROUTES ----------------------------------- */
router.get("/", authRequired, async (_req, res) => {
  try {
    const data = await dbGetAllConfig();
    res.json(data);
  } catch (e) {
    console.error("CFG_GET_ALL_ERR:", e);
    res.status(500).json({ message: "خطا در دریافت داده‌های پایه." });
  }
});
router.get("/titles", authRequired, async (req, res) => {
  try {
    const cid = Number(req.query.category_id || 0);
    if (!cid) return res.status(400).json({ message: "category_id معتبر نیست." });
    const rows = await dbGetTitlesByCategory(cid);
    res.json(rows);
  } catch (e) {
    console.error("CFG_TITLES_ERR:", e);
    res.status(500).json({ message: "خطا در دریافت عناوین." });
  }
});
router.post("/:type", authRequired, allowRoles("system-admin","defense-admin"), async (req, res) => {
  try {
    const type = String(req.params.type || "");
    const name = String(req.body?.name || "").trim();
    const category_id = req.body?.category_id;
    if (!name) return res.status(400).json({ message: "نام الزامی است." });
    const row = await dbAddConfigItem(type, name, category_id);
    res.json(row);
  } catch (e) {
    console.error("CFG_ADD_ERR:", e);
    res.status(500).json({ message: "خطا در افزودن آیتم." });
  }
});
router.put("/:type/:id", authRequired, allowRoles("system-admin","defense-admin"), async (req, res) => {
  try {
    const type = String(req.params.type || "");
    const id   = Number(req.params.id || 0);
    const name = String(req.body?.name || "").trim();
    if (!id || !name) return res.status(400).json({ message: "اطلاعات نامعتبر است." });
    const row = await dbUpdateConfigItem(type, id, name);
    res.json(row);
  } catch (e) {
    console.error("CFG_UPD_ERR:", e);
    res.status(500).json({ message: "خطا در ویرایش آیتم." });
  }
});
router.delete("/:type/:id", authRequired, allowRoles("system-admin","defense-admin"), async (req, res) => {
  try {
    const type = String(req.params.type || "");
    const id   = Number(req.params.id || 0);
    if (!id) return res.status(400).json({ message: "شناسه نامعتبر است." });

    // فقط وقتی title است و نقش defense-admin، محدودیت دامنه را enforce کن
    if (type === "title" && req.user?.role === "defense-admin") {
      const [[row]] = await pool.query(
        "SELECT category_id FROM incident_titles WHERE id = ? LIMIT 1",
        [id]
      );
      if (!row) return res.status(404).json({ message: "عنوان یافت نشد." });
      if (Number(row.category_id) !== 2) {
        return res.status(403).json({ message: "حذف این مورد برای شما مجاز نیست." });
      }
    }

    await dbDeleteConfigItem(type, id);
    res.json({ ok: true });
  } catch (e) {
    console.error("CFG_DEL_ERR:", e);
    res.status(500).json({ message: "خطا در حذف آیتم." });
  }
});
export default router;
