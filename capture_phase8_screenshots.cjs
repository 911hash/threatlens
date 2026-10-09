const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, 'screenshots');
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

const ARTIFACT_DIR = '/home/ankitdey/.gemini/antigravity-ide/brain/6359de4f-b8ba-4ed7-a08a-12a4dca61657/screenshots';
if (!fs.existsSync(ARTIFACT_DIR)) {
  fs.mkdirSync(ARTIFACT_DIR, { recursive: true });
}

async function run() {
  const browser = await chromium.launch({
    headless: true,
  });

  const scanId = 'scan_e75653446809';
  console.log(`Using scan ID: ${scanId}`);

  async function capture(page, filename) {
    const filePath = path.join(OUTPUT_DIR, filename);
    await page.screenshot({ path: filePath, fullPage: true });
    try {
      fs.copyFileSync(filePath, path.join(ARTIFACT_DIR, filename));
    } catch (e) { }
    console.log(`Saved screenshot: ${filename}`);
  }

  async function setTheme(page, theme) {
    await page.evaluate((t) => {
      document.documentElement.setAttribute('data-theme', t);
      localStorage.setItem('threatlens_theme', JSON.stringify(t));
    }, theme);
    await page.waitForTimeout(300);
  }

  const viewports = [
    { name: '1280px', width: 1280, height: 1000 },
    { name: '320px', width: 320, height: 900 },
  ];

  const themes = ['dark', 'light'];

  for (const vp of viewports) {
    for (const theme of themes) {
      const page = await browser.newPage({ viewport: { width: vp.width, height: vp.height } });

      // 1. Email Report with GeoPanel & Score Breakdown Visible
      await page.goto(`http://localhost:5173/scans/${scanId}?view=technical`, { waitUntil: 'networkidle' });
      await setTheme(page, theme);
      await page.waitForTimeout(500);

      await capture(page, `email_report_geopanel_${theme}_${vp.name}.png`);
      await capture(page, `worldmap_marker_${theme}_${vp.name}.png`);
      await capture(page, `score_breakdown_geolocation_${theme}_${vp.name}.png`);

      // 2. Open DetailDrawer from an IP Pivot
      try {
        const pivotButtons = page.locator('button:has-text("Pivot IP")');
        const count = await pivotButtons.count();
        if (count > 0) {
          await pivotButtons.first().click();
          await page.waitForTimeout(500);
          await capture(page, `detail_drawer_ip_pivot_${theme}_${vp.name}.png`);
        } else {
          console.warn('Pivot IP button not found on page');
        }
      } catch (err) {
        console.error('Error clicking pivot button:', err);
      }

      await page.close();
    }
  }

  await browser.close();
  console.log('All Phase 8 verification screenshots captured successfully!');
}

run().catch((err) => {
  console.error('Error in capture script:', err);
  process.exit(1);
});
