// backend/server.js
import express from "express";
import path from "path";
import fs from "fs";
import cors from "cors";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

import helmet from "helmet";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import compression from "compression";
import os from "os"; // برای ساخت FRONTEND URL پیش‌فرض

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app      = express();
const PORT     = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const isProd   = NODE_ENV === "production";

/* ---------------- Core ---------------- */
app.set("trust proxy", 1); // پشت Apache/Reverse Proxy
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

/* ---------------- Helpers ---------------- */
const isSecure = (req) => req.secure || req.headers["x-forwarded-proto"] === "https";

/** PUBLIC_HOSTS=reportserver.karkhe.local,reportserver,localhost
 *  ALLOWED_ORIGINS=https://foo.bar (اختیاری)
 *  ALLOW_SUFFIX=.karkhe.local (اختیاری: اجازه همه زیردامنه‌های این پسوند)
 */
function expandHostsFromEnv() {
  const rawHosts = (process.env.PUBLIC_HOSTS || "")
    .split(",").map(s => s.trim()).filter(Boolean);

  const ports   = ["", `:${PORT}`];
  const schemes = ["http", "https"];
  const out     = new Set();

  for (const host of rawHosts) {
    for (const scheme of schemes) {
      for (const p of ports) out.add(`${scheme}://${host}${p}`);
    }
  }

  (process.env.ALLOWED_ORIGINS || "")
    .split(",").map(s => s.trim()).filter(Boolean)
    .forEach(o => out.add(o));

  return Array.from(out);
}
const allowedOrigins = expandHostsFromEnv();

/* ---------------- CORS ---------------- */
app.use((req, res, next) => {
  // برای عیب‌یابی سریع
  res.setHeader("X-Allowed-Origins", allowedOrigins.join(" "));
  next();
});

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);               // curl / اپ داخلی
    if (allowedOrigins.includes(origin)) return cb(null, true);

    // اجازه‌ی دامنه‌های داخلی با suffix اختیاری
    const allowSuffix = (process.env.ALLOW_SUFFIX || "").trim(); // مثل ".karkhe.local"
    if (allowSuffix) {
      try {
        const u = new URL(origin);
        if (u.hostname.endsWith(allowSuffix)) return cb(null, true);
      } catch {}
    }

    console.warn("[CORS] blocked:", origin);
    return cb(new Error("CORS blocked"));
  },
  credentials: true,
  methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"]
}));

/* ---------------- Helmet پایه (CSP را خودمان تنظیم می‌کنیم) ---------------- */
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginEmbedderPolicy: false,
  originAgentCluster: false,
  referrerPolicy: { policy: "no-referrer" }
}));

/* ---------------- هدرهای امنیتی (داینامیک بر اساس HTTPS) ---------------- */
app.use((req, res, next) => {
  if (isSecure(req)) {
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
    res.setHeader("Origin-Agent-Cluster", "?1");
    res.setHeader("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
  } else {
    res.setHeader("Cross-Origin-Opener-Policy", "unsafe-none");
    res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");
    res.setHeader("Origin-Agent-Cluster", "?0");
    res.setHeader("Strict-Transport-Security", "max-age=0");
  }
  next();
});

/* ---------------- Content-Security-Policy (داینامیک) ---------------- */
app.use((req, res, next) => {
  const directives = {
    "default-src": ["'self'"],

    "script-src": [
      "'self'", "'unsafe-inline'", "'unsafe-eval'",
      "https://cdn.jsdelivr.net",
      "https://code.jquery.com",
      "https://unpkg.com"
    ],
    "script-src-elem": [
      "'self'", "'unsafe-inline'", "'unsafe-eval'",
      "https://cdn.jsdelivr.net",
      "https://code.jquery.com",
      "https://unpkg.com"
    ],

    "style-src": [
      "'self'", "'unsafe-inline'",
      "https://fonts.googleapis.com",
      "https://unpkg.com",
      "https://cdn.jsdelivr.net"
    ],
    "style-src-elem": [
      "'self'", "'unsafe-inline'",
      "https://fonts.googleapis.com",
      "https://unpkg.com",
      "https://cdn.jsdelivr.net"
    ],

    "img-src": [
      "'self'", "data:",
      "https://img.icons8.com",
      "https://cdn.jsdelivr.net"
    ],

    // اجازه پخش مدیا از blob: (و data:) برای پلیرهای مرورگر
    "media-src": [
      "'self'", "blob:", "data:"
    ],

    // اگر از web worker برای ویدیو/پردازش استفاده شود
    "worker-src": [
      "'self'", "blob:"
    ],

    "font-src": [
      "'self'", "data:", "https://fonts.gstatic.com"
    ],

    "connect-src": [
      "'self'",
      "blob:",
      "https://unpkg.com"
    ],

    "frame-ancestors": ["'none'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"]
  };

  if (isSecure(req)) {
    directives["upgrade-insecure-requests"] = [];
  }

  const csp = Object.entries(directives)
    .map(([k, v]) => Array.isArray(v) ? `${k} ${v.join(" ")}` : k)
    .join("; ");

  res.setHeader("Content-Security-Policy", csp);
  next();
});

// nosniff اضافه
app.use((_, res, next) => { res.setHeader("X-Content-Type-Options", "nosniff"); next(); });

/* ---------------- Rate limits / hardening ---------------- */
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 }));
app.use("/api/auth/login", rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }));
app.use("/api/resources",   rateLimit({ windowMs: 10 * 60 * 1000, max: 60 }));
app.use(hpp());
app.use(compression());

/* ---------------- Static: Frontend ---------------- */
const publicDir = path.resolve(__dirname, "../public");
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir, {
    setHeaders: (res, filePath) => {
      const ext = path.extname(filePath).toLowerCase();
      if ([
        ".css",".js",".png",".jpg",".jpeg",".gif",".svg",".webp",".ico",
        ".woff",".woff2",".ttf"
      ].includes(ext)) {
        res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
      } else {
        res.setHeader("Cache-Control", "public, max-age=0");
      }
      res.setHeader("X-Content-Type-Options", "nosniff");
    }
  }));
}

/* ---------------- Files helpers ---------------- */
function encodeRFC5987ValueChars(str = "") {
  return encodeURIComponent(str)
    .replace(/['()]/g, escape)
    .replace(/\*/g, '%2A');
}
const hasNonASCII = (s = "") => /[^\x20-\x7E]/.test(s);

// اگر در .env مسیر مشخص شده باشد، همان؛ وگرنه مسیر پیش‌فرض پروژه
const FILES_DIR =
  process.env.FILES_DIR ||
  process.env.UPLOAD_DIR ||
  path.join(__dirname, "src", "assets", "files");

/* ---------------- Download route (نام سالم) ---------------- */
// این روت قبل از استاتیک ثبت شود
if (fs.existsSync(FILES_DIR)) {
  app.get("/assets/files/download/:name", (req, res) => {
    try {
      const requested = req.params.name || "";
      const safeName = path.basename(decodeURIComponent(requested)); // جلوگیری از traversal
      const abs = path.join(FILES_DIR, safeName);
      if (!abs.startsWith(FILES_DIR) || !fs.existsSync(abs)) {
        return res.status(404).send("Not Found");
      }
      const base = path.basename(abs);

      // فقط filename* برای نام‌های غیر ASCII
      if (hasNonASCII(base)) {
        res.setHeader("Content-Disposition", `attachment; filename*=UTF-8''${encodeRFC5987ValueChars(base)}`);
      } else {
        res.setHeader("Content-Disposition", `attachment; filename="${base.replace(/"/g, "'")}"`);
      }
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
      return res.sendFile(abs);
    } catch {
      return res.status(400).send("Bad Request");
    }
  });
}

/* ---------------- Static: Files (inline streaming) ---------------- */
if (fs.existsSync(FILES_DIR)) {
  app.use("/assets/files", express.static(FILES_DIR, {
    fallthrough: true,
    setHeaders: (res, filePath) => {
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");

      const base = path.basename(filePath);
      const ext  = path.extname(base).toLowerCase();

      // پخش آنلاین = inline (برای ویدیو/آدیو)
      const isMedia = /\.(mp4|webm|mkv|avi|mov|wmv|mp3|wav|ogg|m4a|aac)$/.test(ext);
      const disp = isMedia ? "inline" : "inline";

      // برای نام‌های غیر ASCII فقط filename* بفرست؛ برای ASCII از filename استفاده کن
      if (hasNonASCII(base)) {
        res.setHeader("Content-Disposition", `${disp}; filename*=UTF-8''${encodeRFC5987ValueChars(base)}`);
      } else {
        res.setHeader("Content-Disposition", `${disp}; filename="${base.replace(/"/g, "'")}"`);
      }
    }
  }));
}

/* ---------------- API modules ---------------- */
import authModule      from "./src/modules/auth_module.js";
import usersModule     from "./src/modules/users.module.js";
import configModule    from "./src/modules/config.module.js";
import incidentsModule from "./src/modules/incidents_module.js";
import actionsModule   from "./src/modules/actions_module.js";
import resourcesModule from "./src/modules/resources_module.js";

app.use("/api/auth",      authModule);
app.use("/api/users",     usersModule);
app.use("/api/config",    configModule);
app.use("/api/incidents", incidentsModule);
app.use("/api/actions",   actionsModule);
app.use("/api/resources", resourcesModule);

/* ---------------- SPA fallback ---------------- */
app.get("*", (req, res, next) => {
  const isApi        = req.path.startsWith("/api/");
  const hasExtension = path.extname(req.path) !== "";
  if (req.method !== "GET" || isApi || hasExtension) return next();

  const indexPath = path.join(publicDir, "index.html");
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  return res.status(404).send("Not Found");
});

/* ---------------- Start ---------------- */
app.listen(PORT, "0.0.0.0", () => {
  // ساخت آدرس نمایش reverse proxy به‌شکل امن (بدون template literal تو در تو)
  let frontFromEnv = (process.env.FRONTEND_URL || "").trim();
  if (!frontFromEnv) {
    try {
      frontFromEnv = `http://${os.hostname()}/`;
    } catch {
      frontFromEnv = "http://localhost/";
    }
  }

  console.log("✅ Server running:");
  console.log(`   - http://localhost:${PORT}`);
  console.log("   - via reverse proxy (Apache): " + frontFromEnv);
  console.log(`   NODE_ENV=${NODE_ENV}`);
});
