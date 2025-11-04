// backend/uninstallService.js
import { Service } from 'node-windows';
import path from 'path';

const svc = new Service({
  name: 'Security Incident API',
  description: 'Node.js API backend for Security Incident System',
  script: path.resolve('C:/xampp/htdocs/security-system/backend/server.js')
});

svc.on('uninstall', () => {
  console.log('Service Uninstalled.');
});

svc.uninstall();
