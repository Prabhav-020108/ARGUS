import puppeteer from 'puppeteer';
import { mkdirSync } from 'fs';
import { resolve } from 'path';

const OUT = resolve('scripts/screenshots');
mkdirSync(OUT, { recursive: true });

const VIEWPORTS = [
  { w: 1536, h: 730, label: '1536x730' },
  { w: 1280, h: 800, label: '1280x800' },
  { w: 1024, h: 768, label: '1024x768' },
];

const PAGES = [
  { nav: null,          label: 'overview',    scroll: false },
  { nav: null,          label: 'overview-lower', scroll: true },
  { nav: 'findings',    label: 'findings',    scroll: false },
  { nav: 'dpdp',        label: 'dpdp',        scroll: false },
  { nav: 'remediation', label: 'remediation', scroll: false },
];

async function clickNav(page, pageId) {
  await page.evaluate((id) => {
    const buttons = document.querySelectorAll('aside nav button');
    for (const b of buttons) {
      if (b.textContent.toLowerCase().includes(id)) { b.click(); return; }
    }
  }, pageId);
  await new Promise(r => setTimeout(r, 600));
}

(async () => {
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });

  for (const vp of VIEWPORTS) {
    const page = await browser.newPage();
    await page.setViewport({ width: vp.w, height: vp.h });
    await page.goto('http://localhost:5173/', { waitUntil: 'networkidle0' });
    await new Promise(r => setTimeout(r, 1500));

    // Overview top
    await page.screenshot({ path: `${OUT}/${vp.label}_overview.png` });
    // Overview scroll-down
    await page.evaluate(() => window.scrollBy(0, 600));
    await new Promise(r => setTimeout(r, 300));
    await page.screenshot({ path: `${OUT}/${vp.label}_overview_lower.png` });
    await page.evaluate(() => window.scrollTo(0, 0));

    // Findings
    await clickNav(page, 'findings');
    await page.screenshot({ path: `${OUT}/${vp.label}_findings.png` });

    // DPDP
    await clickNav(page, 'dpdp');
    await page.screenshot({ path: `${OUT}/${vp.label}_dpdp.png` });

    // Remediation
    await clickNav(page, 'remediation');
    await page.screenshot({ path: `${OUT}/${vp.label}_remediation.png` });

    await page.close();
  }

  await browser.close();
  console.log('Screenshots saved to:', OUT);
})();
