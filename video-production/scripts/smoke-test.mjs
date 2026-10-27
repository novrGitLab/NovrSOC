// One-off smoke test: log in via the real staff login form and load the VMS dashboard, to catch
// any runtime errors before building the full capture matrix.
import { chromium } from 'playwright';

const BASE = 'http://localhost:3000';

async function main() {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  page.on('console', (msg) => { if (msg.type() === 'error') console.log('[console error]', msg.text()); });
  page.on('pageerror', (err) => console.log('[page error]', err.message));

  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  await page.fill('input[type="email"], input[name="email"]', 'soc.manager@demo-industries.example');
  await page.fill('input[type="password"], input[name="password"]', 'REN123video2026');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/admin/dashboard**', { timeout: 15000 });
  console.log('Logged in, landed on', page.url());

  await page.goto(`${BASE}/admin/vms`, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: 'scripts/smoke-vms.png', fullPage: false });
  console.log('VMS dashboard screenshot saved.');

  await browser.close();
}

main().catch((err) => { console.error('Fatal:', err); process.exit(1); });
