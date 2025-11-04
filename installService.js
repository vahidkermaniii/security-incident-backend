// backend/installService.js
import { Service } from 'node-windows';
import path from 'path';
import fs from 'fs';

// مسیرهای کلیدی
const SERVER_JS = 'C:/xampp/htdocs/security-system/backend/server.js';
const WORKDIR   = 'C:/xampp/htdocs/security-system/backend';
const LOG_DIR   = 'C:/security-incident-logs';

// اطمینان از وجود فولدر لاگ
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch {}

const svc = new Service({
  name: 'Security Incident API',
  description: 'Node.js API backend for Security Incident System',
  script: path.resolve(SERVER_JS),
  workingDirectory: WORKDIR,
  nodeOptions: ['--max_old_space_size=256'],
  // مسیر لاگ‌ها
  logpath: LOG_DIR,
  // رفتارهای پایداری
  wait: 2,          // بین ری‌استارت‌ها چند ثانیه صبر کند
  grow: 0.5,        // هر بار زمان انتظار را کمی بیشتر کند
  maxRetries: 3,    // بیشینه تلاش برای استارت اولیه
  maxRestarts: 5    // بیشینه ری‌استارت در 24 ساعت
});

// نصب و استارت خودکار
svc.on('install', () => svc.start());
svc.on('alreadyinstalled', () => svc.start());
svc.install();
