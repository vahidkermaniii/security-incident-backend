// backend/src/middleware/upload.js
import path from "path";
import fs from "fs";
import multer from "multer";

// تعیین مسیر ذخیره‌سازی فایل‌ها:
// 1) اگر ENV تعریف شده باشد از آن استفاده کن (FILES_DIR)
// 2) اگر مسیر ویندوزیِ خواسته‌شده وجود داشت از آن
// 3) در غیر این صورت داخل پروژه: backend/src/assets/files
const ENV_FILES_DIR   = process.env.FILES_DIR;
const WINDOWS_PREF    = "C:\\xampp\\htdocs\\security-system\\backend\\src\\assets\\files";
const PROJECT_DEFAULT = path.resolve(process.cwd(), "backend", "src", "assets", "files");

export function getFilesDir() {
  if (ENV_FILES_DIR) return ENV_FILES_DIR;
  if (process.platform === "win32" && fs.existsSync(WINDOWS_PREF)) return WINDOWS_PREF;
  return PROJECT_DEFAULT;
}

const FILES_DIR = getFilesDir();
fs.mkdirSync(FILES_DIR, { recursive: true });

// sanitize نام فایل
function sanitizeName(n = "") {
  return String(n)
    .replace(/[/\\:?*"<>|]+/g, "_") // کاراکترهای خطرناک
    .replace(/\s+/g, " ")
    .trim();
}

// پیدا کردن نام یکتای امن
function uniqueName(base, ext) {
  let name = (base || "file") + (ext || "");
  let i = 1;
  while (fs.existsSync(path.join(FILES_DIR, name))) {
    name = `${base} (${i++})${ext || ""}`;
  }
  return name;
}

// فیلتر نوع فایل (PDF, ویدیوها, پاورپوینت, Word/Excel, تصاویر، متن)
const ALLOWED_EXTS = [
  ".pdf", ".mp4", ".mkv", ".avi", ".mov", ".wmv",
  ".ppt", ".pptx", ".pps", ".ppsx",
  ".doc", ".docx", ".rtf",
  ".xls", ".xlsx", ".csv",
  ".txt", ".md",
  ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp"
];
const MAX_FILE_SIZE = Number(process.env.MAX_UPLOAD_BYTES || 200 * 1024 * 1024); // پیش‌فرض 200MB

function fileFilter(_req, file, cb) {
  const ext = (path.extname(file.originalname) || "").toLowerCase();
  if (!ALLOWED_EXTS.includes(ext)) {
    return cb(new Error("فرمت فایل مجاز نیست."), false);
  }
  cb(null, true);
}

// تعریف Storage
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, FILES_DIR);
  },
  filename: (req, file, cb) => {
    // اگر در فرم فیلد name فرستاده شد، از آن استفاده کن؛ وگرنه originalname
    const originalExt = (path.extname(file.originalname) || "").toLowerCase();
    const given = sanitizeName(req.body?.name || "");
    const base = sanitizeName(given ? path.basename(given, originalExt) : path.basename(file.originalname, originalExt));
    const finalName = uniqueName(base || "file", originalExt);
    cb(null, finalName);
  }
});

// خود Multer
const uploader = multer({
  storage,
  fileFilter,
  limits: { fileSize: MAX_FILE_SIZE },
});

// میدل‌ویر کمکی برای تزریق مسیر فایل‌ها (کنترلرها به req._FILES_DIR دسترسی داشته باشند)
function injectFilesDir(req, _res, next) {
  req._FILES_DIR = FILES_DIR;
  next();
}

// استفاده‌ی مرسوم: uploadFile = single('file')
export const uploadFile = [
  injectFilesDir,
  uploader.single("file")
];

// در صورت نیاز برای چند فایل:
// export const uploadFiles = [
//   injectFilesDir,
//   uploader.array("files", 10)
// ];

export default uploadFile;
