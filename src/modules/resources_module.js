// backend/src/modules/resources_module.js
import express, { Router } from "express";
import path from "path";
import fs from "fs";
import multer from "multer";
import { auth as authRequired, allowRoles } from "../middleware/auth.js";
import { pool } from "../config/db.js";

const router = Router();

/* ---------------------------------- MODEL --------------------------------- */
const SELECT_BASE = `
  SELECT id, title, domain, category, filename, mime, ext, size,
         DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at,
         DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s') AS updated_at
  FROM resources
`;

async function dbListAll({ domain } = {}) {
  if (domain && (domain === "cyber" || domain === "physical")) {
    const [rows] = await pool.query(SELECT_BASE + " WHERE domain=? ORDER BY id DESC", [domain]);
    return rows;
  }
  const [rows] = await pool.query(SELECT_BASE + " ORDER BY id DESC");
  return rows;
}

async function dbGetById(id) {
  const [rows] = await pool.query(SELECT_BASE + " WHERE id = ?", [id]);
  return rows?.[0] || null;
}

async function dbCreate({ title, domain, category, filename, mime, ext, size, created_by }) {
  const [ins] = await pool.query(
    `INSERT INTO resources (title, domain, category, filename, mime, ext, size, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
    [title, domain, category, filename, mime, ext, size, created_by || null]
  );
  return dbGetById(ins.insertId);
}

async function dbUpdate(id, fields = {}) {
  const sets = [], params = [];
  if (fields.title !== undefined)    { sets.push("title=?");    params.push(fields.title); }
  if (fields.domain !== undefined)   { sets.push("domain=?");   params.push(fields.domain); }
  if (fields.category !== undefined) { sets.push("category=?"); params.push(fields.category); }
  if (fields.filename !== undefined) { sets.push("filename=?"); params.push(fields.filename); }
  if (fields.mime !== undefined)     { sets.push("mime=?");     params.push(fields.mime); }
  if (fields.ext !== undefined)      { sets.push("ext=?");      params.push(fields.ext); }
  if (fields.size !== undefined)     { sets.push("size=?");     params.push(fields.size); }
  if (!sets.length) return dbGetById(id);
  sets.push("updated_at=NOW()");
  params.push(id);
  await pool.query(`UPDATE resources SET ${sets.join(", ")} WHERE id=?`, params);
  return dbGetById(id);
}

async function dbRemove(id) {
  await pool.query("DELETE FROM resources WHERE id=?", [id]);
  return true;
}

/* ---------------------------------- FILES --------------------------------- */
const ENV_FILES_DIR     = process.env.FILES_DIR;
const DEFAULT_FILES_DIR = path.resolve(process.cwd(), "src", "assets", "files");
const WINDOWS_PREF      = "C:\\xampp\\htdocs\\security-system\\backend\\src\\assets\\files";
const FILES_DIR         = ENV_FILES_DIR || (fs.existsSync(WINDOWS_PREF) ? WINDOWS_PREF : DEFAULT_FILES_DIR);
fs.mkdirSync(FILES_DIR, { recursive: true });
// (اختیاری برای تست)
console.log("📂 FILES_DIR =", FILES_DIR);

function sanitizeName(n = "") {
  return String(n).replace(/[\/\\:?*"<>|]+/g, "_").replace(/\s+/g, " ").trim();
}
function uniqueName(base, ext) {
  let candidate = base + ext, i = 1;
  while (fs.existsSync(path.join(FILES_DIR, candidate))) candidate = `${base} (${i++})${ext}`;
  return candidate;
}

/* ------------------------- Fix mojibake on upload ------------------------- */
function decodeUtf8FromLatin1(s = "") {
  try { return Buffer.from(String(s), "latin1").toString("utf8"); } catch { return s; }
}

/* ------------------------------ Multer setup ------------------------------ */
/** 🔒 MIMEهای مجاز برای آپلود (SVG/HTML عمدی حذف شده‌اند) */
const ALLOWED = {
  pdf:  ["application/pdf"],
  video:["video/mp4","video/webm","video/x-matroska","video/quicktime","video/x-ms-wmv","video/x-msvideo"],
  ppt:  ["application/vnd.openxmlformats-officedocument.presentationml.presentation","application/vnd.ms-powerpoint"],
  word: ["application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document","application/rtf"],
  excel:["application/vnd.ms-excel","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","text/csv"],
  image:["image/jpeg","image/png","image/gif","image/webp"]
};
const ALLOWED_SET = new Set(Object.values(ALLOWED).flat());

const UPLOAD_LIMIT_MB = Number(process.env.UPLOAD_MAX_MB || 150);
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, FILES_DIR),
  filename: (req, file, cb) => {
    const raw = decodeUtf8FromLatin1(file.originalname || "file");
    const ext = path.extname(raw);
    const base = sanitizeName(path.basename(raw, ext) || "file");
    cb(null, uniqueName(base, ext || ""));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: UPLOAD_LIMIT_MB * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const mt = String(file.mimetype || "").toLowerCase();
    if (ALLOWED_SET.has(mt)) return cb(null, true);
    return cb(new multer.MulterError("LIMIT_UNEXPECTED_FILE", "file"));
  }
});

const SUPPORTED_TYPES = [
  { value: "pdf",        label: "PDF",        exts: ["pdf"] },
  { value: "video",      label: "ویدیو",      exts: ["mp4","mkv","avi","mov","wmv","webm"] },
  { value: "powerpoint", label: "PowerPoint", exts: ["ppt","pptx","pps","ppsx"] },
  { value: "word",       label: "Word",       exts: ["doc","docx","rtf"] },
  { value: "excel",      label: "Excel",      exts: ["xls","xlsx","csv"] },
  // 🔒 SVG حذف شد
  { value: "image",      label: "تصویر",      exts: ["jpg","jpeg","png","gif","webp"] },
  { value: "other",      label: "سایر",       exts: [] },
];

const normDomain = (d) => (d === "physical" || d === "cyber") ? d : "cyber";
const normCategory = (c) => {
  const t = String(c || "").trim().toLowerCase();
  return SUPPORTED_TYPES.some(x => x.value === t) ? t : "";
};
function inferCategoryByExt(ext) {
  const e = (ext || "").replace(/^\./,"").toLowerCase();
  for (const t of SUPPORTED_TYPES) if (t.exts.includes(e)) return t.value;
  return "other";
}
const filePublicUrl = (fname) => `/assets/files/${encodeURIComponent(path.basename(String(fname)))}`;

/* --------------------------------- HELPERS -------------------------------- */
/** 🔒 جلوگیری از Path Traversal */
function safeJoin(base, target) {
  const full = path.resolve(base, String(target || ""));
  if (!full.startsWith(base)) throw new Error("Path traversal detected");
  return full;
}
function getMimeByExt(ext) {
  const e = (ext || "").replace(/^\./,"").toLowerCase();
  if (e === "pdf") return "application/pdf";
  if (["mp4","webm","mkv","avi","mov","wmv"].includes(e)) return "video/" + (e === "mkv" ? "x-matroska" : (e === "wmv" ? "x-ms-wmv" : (e === "avi" ? "x-msvideo" : e)));
  if (["ppt","pps"].includes(e)) return "application/vnd.ms-powerpoint";
  if (["pptx","ppsx"].includes(e)) return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
  if (["doc"].includes(e)) return "application/msword";
  if (["docx"].includes(e)) return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  if (["rtf"].includes(e)) return "application/rtf";
  if (["xls"].includes(e)) return "application/vnd.ms-excel";
  if (["xlsx"].includes(e)) return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
  if (["csv"].includes(e)) return "text/csv";
  if (["jpg","jpeg"].includes(e)) return "image/jpeg";
  if (["png"].includes(e)) return "image/png";
  if (["gif"].includes(e)) return "image/gif";
  if (["webp"].includes(e)) return "image/webp";
  return "application/octet-stream";
}

// 🔤 کمک‌تابع‌های هدر UTF-8
function encodeRFC5987ValueChars(str = "") {
  return encodeURIComponent(str)
    .replace(/['()]/g, escape)
    .replace(/\*/g, "%2A");
}
const hasNonASCII = (s = "") => /[^\x20-\x7E]/.test(String(s || ""));

function ensureDefenseOwnsPhysicalOr403(req, res, resource) {
  if (req.user?.role === "defense-admin") {
    if (resource?.domain !== "physical") {
      res.status(403).json({ message: "اجازهٔ انجام این عملیات روی محتوای غیرپدافندی را ندارید." });
      return false;
    }
  }
  return true;
}

/* --------------------------------- STATIC --------------------------------- */
// 🔒 سرو استاتیک با attachment + nosniff (برای جلوگیری از اجرای مستقیم محتوای فعال)
router.use("/assets/files", express.static(FILES_DIR, {
  fallthrough: true,
  setHeaders: (res, filePath) => {
    res.setHeader("X-Content-Type-Options","nosniff");
    const base = path.basename(filePath);
    // برای سازگاری بیشتر، هر دو کلید را می‌فرستیم؛ مرورگرهای جدید از filename* استفاده می‌کنند
    res.setHeader("Content-Disposition",
      `attachment; filename="${base.replace(/"/g,"'")}"; filename*=UTF-8''${encodeRFC5987ValueChars(base)}`
    );
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  }
}));

/* --------------------------------- ROUTES --------------------------------- */
// انواع فایل برای سلکت
router.get("/types", authRequired, async (_req, res) => {
  res.json(SUPPORTED_TYPES);
});

// لیست منابع (اختیاری: ?domain=cyber|physical)
router.get("/", authRequired, async (req, res) => {
  try {
    const domain = (req.query?.domain || "").toString();
    const rows = await dbListAll({ domain: (domain === "cyber" || domain === "physical") ? domain : undefined });
    res.json(rows.map(r => ({ ...r, url: filePublicUrl(r.filename) })));
  } catch (e) {
    console.error("RES_LIST_ERR:", e);
    res.status(500).json({ message: "خطا در بارگذاری لیست فایل‌های آموزشی." });
  }
});

// دانلود/مشاهده فایل (قدیمی: با نام فایل؛ اجباری به‌صورت attachment)
router.get("/file/:name", authRequired, async (req, res) => {
  try {
    const fileName = req.params.name;
    if (!fileName || /[\/\\]/.test(fileName)) return res.status(400).json({ message: "نام فایل نامعتبر است." });

    const full = safeJoin(FILES_DIR, fileName);
    if (!fs.existsSync(full)) return res.status(404).json({ message: "فایل یافت نشد." });

    const ext  = path.extname(full);
    const mime = getMimeByExt(ext);

    res.setHeader("X-Content-Type-Options","nosniff");
    res.setHeader("Content-Type", mime || "application/octet-stream");
    res.setHeader("Content-Disposition",
      `attachment; filename="${path.basename(full).replace(/"/g,"'")}"; filename*=UTF-8''${encodeRFC5987ValueChars(path.basename(full))}`
    );
    res.sendFile(full);
  } catch (e) {
    console.error("RES_FILE_ERR:", e);
    res.status(500).json({ message: "خطا در ارائه فایل." });
  }
});

/* ------------------------ NEW: نمایش و دانلود بر اساس id ------------------------ */
// ✅ نمایش در مرورگر (inline)
router.get("/view/:id", authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) {
      return res.status(400).json({ message: "شناسه نامعتبر است." });
    }

    const file = await dbGetById(id);
    if (!file) return res.status(404).json({ message: "فایل یافت نشد." });

    const absPath = path.resolve(FILES_DIR, file.filename);
    if (!fs.existsSync(absPath)) {
      console.warn("⚠ فایل وجود ندارد:", absPath);
      return res.status(404).json({ message: "فایل وجود ندارد." });
    }

    const ext = path.extname(absPath).toLowerCase();
    const mime =
      (file.mime && String(file.mime).trim()) ||
      getMimeByExt(file.ext || ext) ||
      "application/octet-stream";

    res.setHeader("Content-Type", mime);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "private, max-age=0, must-revalidate");

    // فقط filename* برای جلوگیری از کاراکتر غیر ASCII در هدر
    const base = path.basename(absPath);
    res.setHeader(
      "Content-Disposition",
      `inline; filename*=UTF-8''${encodeURIComponent(base)}`
    );

    // ✅ استفاده از fs.createReadStream بجای sendFile (پایدار در ویندوز)
    const stream = fs.createReadStream(absPath);
    stream.on("error", (err) => {
      console.error("📛 RES_VIEW_STREAM_ERR:", err);
      if (err.code === "ENOENT") {
        return res.status(404).json({ message: "فایل یافت نشد." });
      }
      return res.status(500).json({ message: "خطا در نمایش فایل." });
    });
    stream.pipe(res);
  } catch (e) {
    console.error("📛 RES_VIEW_ERR:", e);
    res.status(500).json({ message: "خطا در نمایش فایل." });
  }
});

// ✅ دانلود (attachment) — پایدار با استریم + UTF-8
router.get("/download/:id", authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) {
      return res.status(400).json({ message: "شناسه نامعتبر است." });
    }

    const file = await dbGetById(id);
    if (!file) return res.status(404).json({ message: "فایل یافت نشد." });

    const absPath = path.resolve(FILES_DIR, file.filename);
    if (!fs.existsSync(absPath)) {
      return res.status(404).json({ message: "فایل وجود ندارد." });
    }

    const base = path.basename(absPath);
    const ext  = path.extname(absPath).toLowerCase();
    const mime =
      (file.mime && String(file.mime).trim()) ||
      getMimeByExt(file.ext || ext) ||
      "application/octet-stream";

    // اندازه برای بعضی پراکسی‌ها
    try {
      const stat = fs.statSync(absPath);
      if (stat?.size) res.setHeader("Content-Length", String(stat.size));
    } catch {}

    res.setHeader("Content-Type", mime);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "private, max-age=0, must-revalidate");
    // ⚠️ فقط filename* = UTF-8 (بدون filename= تا با فارسی گیر نده)
    res.setHeader("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(base)}`);

    const stream = fs.createReadStream(absPath);
    stream.on("error", (err) => {
      console.error("📛 RES_DOWNLOAD_STREAM_ERR:", err);
      if (err.code === "ENOENT") return res.status(404).json({ message: "فایل یافت نشد." });
      return res.status(500).json({ message: "خطا در دانلود فایل." });
    });
    stream.pipe(res);
  } catch (e) {
    console.error("📛 RES_DOWNLOAD_ERR:", e);
    res.status(500).json({ message: "خطا در دانلود فایل." });
  }
});




/* ------------------------------ CRUD endpoints ----------------------------- */
// ایجاد (system-admin و defense-admin — ولی defense فقط physical)
router.post("/", authRequired, allowRoles("system-admin","defense-admin"), upload.single("file"), async (req, res) => {
  try {
    const { title } = req.body || {};
    let { domain, category } = req.body || {};
    if (!title?.trim()) return res.status(400).json({ message: "عنوان الزامی است." });
    if (!req.file)      return res.status(400).json({ message: "فایل ارسال نشده است." });

    // نقش defense-admin فقط physical می‌تواند
    if (req.user?.role === "defense-admin") domain = "physical";
    const finalDomain = normDomain(domain);

    const ext = (path.extname(req.file.filename) || "").toLowerCase();
    const guessed = inferCategoryByExt(ext);
    const finalCategory = normCategory(category) || guessed;

    const created = await dbCreate({
      title: String(title).trim(),
      domain: finalDomain,
      category: finalCategory,
      filename: req.file.filename,
      mime: req.file.mimetype || "",
      ext,
      size: Number(req.file.size || 0),
      created_by: req.user?.id || null,
    });
    res.status(201).json({ ...created, url: filePublicUrl(created.filename) });
  } catch (e) {
    console.error("RES_CREATE_ERR:", e);
    if (e instanceof multer.MulterError && e.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({ message: "حجم فایل بیش از حد مجاز است." });
    }
    if (e instanceof multer.MulterError && e.code === "LIMIT_UNEXPECTED_FILE") {
      return res.status(415).json({ message: "نوع فایل مجاز نیست." });
    }
    res.status(500).json({ message: "ثبت فایل آموزشی با خطا مواجه شد." });
  }
});

// ویرایش (system-admin کامل؛ defense-admin فقط اگر resource.physical باشد)
router.put("/:id", authRequired, allowRoles("system-admin","defense-admin"), upload.single("file"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });

    const exist = await dbGetById(id);
    if (!exist) return res.status(404).json({ message: "مطلب یافت نشد." });
    if (!ensureDefenseOwnsPhysicalOr403(req, res, exist)) return;

    const fields = {};
    if (req.body?.title !== undefined)    fields.title = String(req.body.title).trim();

    // اگر defense-admin بود، اجازه تغییر domain به غیر physical ندارد
    if (req.body?.domain !== undefined) {
      const dom = normDomain(req.body.domain);
      if (req.user?.role === "defense-admin" && dom !== "physical") {
        return res.status(403).json({ message: "تغییر دامنه به غیرپدافندی مجاز نیست." });
      }
      fields.domain = dom;
    }

    if (req.body?.category !== undefined) {
      const cat = normCategory(req.body.category);
      fields.category = cat || inferCategoryByExt(req.file ? path.extname(req.file.filename) : exist.ext);
    }

    if (req.file) {
      fields.filename = req.file.filename;
      fields.mime = req.file.mimetype || "";
      fields.ext = (path.extname(req.file.filename) || "").toLowerCase();
      fields.size = Number(req.file.size || 0);

      const oldFull = safeJoin(FILES_DIR, exist.filename);
      if (fs.existsSync(oldFull)) { try { fs.unlinkSync(oldFull); } catch {} }
      if (fields.category === undefined) fields.category = inferCategoryByExt(fields.ext);
    }

    const updated = await dbUpdate(id, fields);
    res.json({ ...updated, url: filePublicUrl(updated.filename) });
  } catch (e) {
    console.error("RES_UPDATE_ERR:", e);
    if (e instanceof multer.MulterError && e.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({ message: "حجم فایل بیش از حد مجاز است." });
    }
    if (e instanceof multer.MulterError && e.code === "LIMIT_UNEXPECTED_FILE") {
      return res.status(415).json({ message: "نوع فایل مجاز نیست." });
    }
    res.status(500).json({ message: "ویرایش فایل آموزشی با خطا مواجه شد." });
  }
});

// حذف (system-admin کامل؛ defense-admin فقط اگر resource.physical باشد)
router.delete("/:id", authRequired, allowRoles("system-admin","defense-admin"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });

    const exist = await dbGetById(id);
    if (!exist) return res.status(404).json({ message: "مطلب یافت نشد." });
    if (!ensureDefenseOwnsPhysicalOr403(req, res, exist)) return;

    const full = safeJoin(FILES_DIR, exist.filename);
    if (fs.existsSync(full)) { try { fs.unlinkSync(full); } catch {} }

    await dbRemove(id);
    res.json({ ok: true });
  } catch (e) {
    console.error("RES_DELETE_ERR:", e);
    res.status(500).json({ message: "حذف فایل آموزشی با خطا مواجه شد." });
  }
});

export default router;
