// backend/src/modules/resources_module.js
import express, { Router } from "express";
import path, { dirname } from "path";
import fs from "fs";
import multer from "multer";
import { fileURLToPath } from "url";
import { createClient } from "@supabase/supabase-js";
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

/* --------------------------- STORAGE: LOCAL / SUPA ------------------------- */
const __dirname = dirname(fileURLToPath(import.meta.url));

const USE_SUPABASE = !!process.env.SUPABASE_URL && !!process.env.SUPABASE_KEY;
const SUPA_URL     = process.env.SUPABASE_URL || "";
const SUPA_KEY     = process.env.SUPABASE_KEY || "";
const SUPA_BUCKET  = process.env.SUPABASE_BUCKET || "resources";
const supa = USE_SUPABASE ? createClient(SUPA_URL, SUPA_KEY) : null;

const ROUTE_BASE = process.env.RESOURCES_ROUTE_BASE || "/api/resources";

// Local FS fallback (module-relative, not process.cwd)
const ENV_FILES_DIR     = process.env.FILES_DIR;
const DEFAULT_FILES_DIR = path.resolve(__dirname, "../assets/files");
const WINDOWS_PREF      = "C:\\xampp\\htdocs\\security-system\\backend\\assets\\files";
const FILES_DIR         = ENV_FILES_DIR || (fs.existsSync(WINDOWS_PREF) ? WINDOWS_PREF : DEFAULT_FILES_DIR);
if (!USE_SUPABASE) {
  fs.mkdirSync(FILES_DIR, { recursive: true });
}
console.log("📦 STORAGE =", USE_SUPABASE ? `Supabase bucket "${SUPA_BUCKET}"` : `Local FS -> ${FILES_DIR}`);

/* --------------------------------- HELPERS -------------------------------- */
function sanitizeName(n = "") {
  return String(n).replace(/[\/\\:?*"<>|]+/g, "_").replace(/\s+/g, " ").trim();
}
function uniqueName(base, ext) {
  let candidate = base + ext, i = 1;
  while (fs.existsSync(path.join(FILES_DIR, candidate))) candidate = `${base} (${i++})${ext}`;
  return candidate;
}

/* Mojibake fix */
function decodeUtf8FromLatin1(s = "") {
  try { return Buffer.from(String(s), "latin1").toString("utf8"); } catch { return s; }
}

/* MIME allowlist */
const ALLOWED = {
  pdf:  ["application/pdf"],
  video:["video/mp4","video/webm","video/x-matroska","video/quicktime","video/x-ms-wmv","video/x-msvideo"],
  ppt:  ["application/vnd.openxmlformats-officedocument.presentationml.presentation","application/vnd.ms-powerpoint"],
  word: ["application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document","application/rtf"],
  excel:["application/vnd.ms-excel","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","text/csv"],
  image:["image/jpeg","image/png","image/gif","image/webp"]
};
const ALLOWED_SET = new Set(Object.values(ALLOWED).flat());

const SUPPORTED_TYPES = [
  { value: "pdf",        label: "PDF",        exts: ["pdf"] },
  { value: "video",      label: "ویدیو",      exts: ["mp4","mkv","avi","mov","wmv","webm"] },
  { value: "powerpoint", label: "PowerPoint", exts: ["ppt","pptx","pps","ppsx"] },
  { value: "word",       label: "Word",       exts: ["doc","docx","rtf"] },
  { value: "excel",      label: "Excel",      exts: ["xls","xlsx","csv"] },
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
const filePublicUrlLocal = (fname) =>
  `${ROUTE_BASE}/assets/files/${encodeURIComponent(path.basename(String(fname)))}`;

function safeJoin(base, target) {
  const full = path.resolve(base, String(target || ""));
  if (!full.startsWith(base)) throw new Error("Path traversal detected");
  return full;
}
function getMimeByExt(ext) {
  const e = (ext || "").replace(/^\./,"").toLowerCase();
  if (e === "pdf") return "application/pdf";
  if (["mp4","webm","mkv","avi","mov","wmv"].includes(e))
    return "video/" + (e === "mkv" ? "x-matroska" : (e === "wmv" ? "x-ms-wmv" : (e === "avi" ? "x-msvideo" : e)));
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

function encodeRFC5987ValueChars(str = "") {
  return encodeURIComponent(str).replace(/['()]/g, escape).replace(/\*/g, "%2A");
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

/* ------------------------------ Multer setup ------------------------------ */
const UPLOAD_LIMIT_MB = Number(process.env.UPLOAD_MAX_MB || 150);

const storage = USE_SUPABASE
  ? multer.memoryStorage()
  : multer.diskStorage({
      destination: (_req, _file, cb) => cb(null, FILES_DIR),
      filename: (_req, file, cb) => {
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

/* --------------------------- Static (LOCAL only) --------------------------- */
if (!USE_SUPABASE) {
  router.use("/assets/files", express.static(FILES_DIR, {
    fallthrough: true,
    setHeaders: (res, filePath) => {
      res.setHeader("X-Content-Type-Options","nosniff");
      const base = path.basename(filePath);
      res.setHeader("Content-Disposition",
        `attachment; filename="${base.replace(/"/g,"'")}"; filename*=UTF-8''${encodeRFC5987ValueChars(base)}`
      );
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    }
  }));
}

/* --------------------------------- ROUTES --------------------------------- */
// انواع فایل برای سلکت
router.get("/types", authRequired, async (_req, res) => {
  res.json(SUPPORTED_TYPES);
});

// لیست منابع (?domain=cyber|physical)
router.get("/", authRequired, async (req, res) => {
  try {
    const domain = (req.query?.domain || "").toString();
    const rows = await dbListAll({ domain: (domain === "cyber" || domain === "physical") ? domain : undefined });

    if (!USE_SUPABASE) {
      return res.json(rows.map(r => ({ ...r, url: filePublicUrlLocal(r.filename) })));
    }

    const out = rows.map(r => {
      const { data } = supa.storage.from(SUPA_BUCKET).getPublicUrl(r.filename);
      return { ...r, url: data.publicUrl };
    });
    res.json(out);
  } catch (e) {
    console.error("RES_LIST_ERR:", e);
    res.status(500).json({ message: "خطا در بارگذاری لیست فایل‌های آموزشی." });
  }
});

// دانلود/مشاهده (قدیمی با نام فایل) — فقط LOCAL
router.get("/file/:name", authRequired, async (req, res) => {
  if (USE_SUPABASE) return res.status(410).json({ message: "این مسیر در حالت Supabase فعال نیست." });
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
// نمایش inline
router.get("/view/:id", authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });

    const file = await dbGetById(id);
    if (!file) return res.status(404).json({ message: "فایل یافت نشد." });

    if (USE_SUPABASE) {
      const { data } = supa.storage.from(SUPA_BUCKET).getPublicUrl(file.filename);
      return res.redirect(302, data.publicUrl);
    }

    const absPath = path.resolve(FILES_DIR, file.filename);
    if (!fs.existsSync(absPath)) {
      console.warn("⚠ فایل وجود ندارد:", absPath);
      return res.status(404).json({ message: "فایل وجود ندارد." });
    }

    const ext = path.extname(absPath).toLowerCase();
    const mime = (file.mime && String(file.mime).trim()) || getMimeByExt(file.ext || ext) || "application/octet-stream";

    res.setHeader("Content-Type", mime);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "private, max-age=0, must-revalidate");
    const base = path.basename(absPath);
    res.setHeader("Content-Disposition", `inline; filename*=UTF-8''${encodeURIComponent(base)}`);

    const stream = fs.createReadStream(absPath);
    stream.on("error", (err) => {
      console.error("📛 RES_VIEW_STREAM_ERR:", err);
      if (err.code === "ENOENT") return res.status(404).json({ message: "فایل یافت نشد." });
      return res.status(500).json({ message: "خطا در نمایش فایل." });
    });
    stream.pipe(res);
  } catch (e) {
    console.error("📛 RES_VIEW_ERR:", e);
    res.status(500).json({ message: "خطا در نمایش فایل." });
  }
});

// دانلود attachment
router.get("/download/:id", authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });

    const file = await dbGetById(id);
    if (!file) return res.status(404).json({ message: "فایل یافت نشد." });

    if (USE_SUPABASE) {
      // Public bucket: redirect به publicUrl کافی است
      const { data } = supa.storage.from(SUPA_BUCKET).getPublicUrl(file.filename);
      return res.redirect(302, data.publicUrl);
      // اگر باکت private شد:
      // const { data, error } = await supa.storage.from(SUPA_BUCKET).createSignedUrl(file.filename, 60);
      // if (error) return res.status(500).json({ message: "خطا در لینک دانلود." });
      // return res.redirect(302, data.signedUrl);
    }

    const absPath = path.resolve(FILES_DIR, file.filename);
    if (!fs.existsSync(absPath)) return res.status(404).json({ message: "فایل وجود ندارد." });

    const base = path.basename(absPath);
    const ext  = path.extname(absPath).toLowerCase();
    const mime = (file.mime && String(file.mime).trim()) || getMimeByExt(file.ext || ext) || "application/octet-stream";

    try {
      const stat = fs.statSync(absPath);
      if (stat?.size) res.setHeader("Content-Length", String(stat.size));
    } catch {}

    res.setHeader("Content-Type", mime);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "private, max-age=0, must-revalidate");
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
// ایجاد
router.post("/", authRequired, allowRoles("system-admin","defense-admin"), upload.single("file"), async (req, res) => {
  try {
    const { title } = req.body || {};
    let { domain, category } = req.body || {};
    if (!title?.trim()) return res.status(400).json({ message: "عنوان الزامی است." });
    if (!req.file)      return res.status(400).json({ message: "فایل ارسال نشده است." });

    if (req.user?.role === "defense-admin") domain = "physical";
    const finalDomain = normDomain(domain);

    // برای Supabase از originalname؛ برای local از نام فایل دیسک
    const rawName = decodeUtf8FromLatin1(req.file.originalname || req.file.filename || "file");
    const ext = (path.extname(rawName) || "").toLowerCase();
    const guessed = inferCategoryByExt(ext);
    const finalCategory = normCategory(category) || guessed;

    let savedFilename, mime, size;

    if (USE_SUPABASE) {
      const key = `${finalDomain}/${Date.now()}_${Math.random().toString(36).slice(2)}${ext}`;
      const contentType = req.file.mimetype || getMimeByExt(ext);
      const { error } = await supa.storage.from(SUPA_BUCKET).upload(key, req.file.buffer, { contentType, upsert: false });
      if (error) throw error;
      savedFilename = key; // DB: کلید داخل باکت
      mime = contentType;
      size = req.file.size || req.file.buffer?.length || 0;
    } else {
      savedFilename = req.file.filename;
      mime = req.file.mimetype || "";
      size = Number(req.file.size || 0);
    }

    const created = await dbCreate({
      title: String(title).trim(),
      domain: finalDomain,
      category: finalCategory,
      filename: savedFilename,
      mime,
      ext,
      size,
      created_by: req.user?.id || null,
    });

    let url;
    if (USE_SUPABASE) {
      const { data } = supa.storage.from(SUPA_BUCKET).getPublicUrl(savedFilename);
      url = data.publicUrl;
    } else {
      url = filePublicUrlLocal(created.filename);
    }

    res.status(201).json({ ...created, url });
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

// ویرایش
router.put("/:id", authRequired, allowRoles("system-admin","defense-admin"), upload.single("file"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });

    const exist = await dbGetById(id);
    if (!exist) return res.status(404).json({ message: "مطلب یافت نشد." });
    if (!ensureDefenseOwnsPhysicalOr403(req, res, exist)) return;

    const fields = {};
    if (req.body?.title !== undefined)    fields.title = String(req.body.title).trim();

    if (req.body?.domain !== undefined) {
      const dom = normDomain(req.body.domain);
      if (req.user?.role === "defense-admin" && dom !== "physical") {
        return res.status(403).json({ message: "تغییر دامنه به غیرپدافندی مجاز نیست." });
      }
      fields.domain = dom;
    }

    if (req.body?.category !== undefined) {
      const cat = normCategory(req.body.category);
      fields.category = cat || inferCategoryByExt(req.file ? path.extname(decodeUtf8FromLatin1(req.file.originalname || req.file.filename)) : exist.ext);
    }

    if (req.file) {
      if (USE_SUPABASE) {
        // upload new
        const rawName = decodeUtf8FromLatin1(req.file.originalname || "file");
        const ext = (path.extname(rawName) || "").toLowerCase();
        const key = `${(fields.domain || exist.domain || "cyber")}/${Date.now()}_${Math.random().toString(36).slice(2)}${ext}`;
        const contentType = req.file.mimetype || getMimeByExt(ext);
        const { error } = await supa.storage.from(SUPA_BUCKET).upload(key, req.file.buffer, { contentType, upsert: false });
        if (error) throw error;

        // delete old
        if (exist.filename) {
          try { await supa.storage.from(SUPA_BUCKET).remove([exist.filename]); } catch {}
        }

        fields.filename = key;
        fields.mime = contentType;
        fields.ext = ext;
        fields.size = req.file.size || req.file.buffer?.length || 0;
        if (fields.category === undefined) fields.category = inferCategoryByExt(ext);
      } else {
        // LOCAL
        fields.filename = req.file.filename;
        fields.mime = req.file.mimetype || "";
        fields.ext = (path.extname(req.file.filename) || "").toLowerCase();
        fields.size = Number(req.file.size || 0);

        const oldFull = safeJoin(FILES_DIR, exist.filename);
        if (fs.existsSync(oldFull)) { try { fs.unlinkSync(oldFull); } catch {} }
        if (fields.category === undefined) fields.category = inferCategoryByExt(fields.ext);
      }
    }

    const updated = await dbUpdate(id, fields);

    let url;
    if (USE_SUPABASE) {
      const { data } = supa.storage.from(SUPA_BUCKET).getPublicUrl(updated.filename);
      url = data.publicUrl;
    } else {
      url = filePublicUrlLocal(updated.filename);
    }

    res.json({ ...updated, url });
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

// حذف
router.delete("/:id", authRequired, allowRoles("system-admin","defense-admin"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ message: "شناسه نامعتبر است." });

    const exist = await dbGetById(id);
    if (!exist) return res.status(404).json({ message: "مطلب یافت نشد." });
    if (!ensureDefenseOwnsPhysicalOr403(req, res, exist)) return;

    if (USE_SUPABASE) {
      if (exist.filename) {
        try { await supa.storage.from(SUPA_BUCKET).remove([exist.filename]); } catch {}
      }
    } else {
      const full = safeJoin(FILES_DIR, exist.filename);
      if (fs.existsSync(full)) { try { fs.unlinkSync(full); } catch {} }
    }

    await dbRemove(id);
    res.json({ ok: true });
  } catch (e) {
    console.error("RES_DELETE_ERR:", e);
    res.status(500).json({ message: "حذف فایل آموزشی با خطا مواجه شد." });
  }
});

export default router;
