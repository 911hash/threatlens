const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, 'screenshots');
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

const ARTIFACT_DIR = '/home/ankitdey/.gemini/antigravity-ide/brain/3752bfbd-e9a5-4aa2-8f4c-b2efeb53103f';

async function run() {
  const browser = await chromium.launch({
    headless: true,
  });

  const phishScanId = 'scan_345e55d15b39';
  const trackingScanId = 'scan_c179a0d8b609';

  console.log('Capturing screenshots for ThreatLens Phase 7.5...');

  // Helper function to capture screenshot
  async function capture(page, name, filename) {
    const filePath = path.join(OUTPUT_DIR, filename);
    await page.screenshot({ path: filePath, fullPage: true });
    // Also copy to artifact dir if exists
    try {
      if (fs.existsSync(ARTIFACT_DIR)) {
        fs.copyFileSync(filePath, path.join(ARTIFACT_DIR, filename));
      }
    } catch (e) {}
    console.log(`Saved: ${filename}`);
  }

  // Helper to toggle theme to light or dark
  async function setTheme(page, theme) {
    await page.evaluate((t) => {
      document.documentElement.setAttribute('data-theme', t);
      localStorage.setItem('threatlens_theme', JSON.stringify(t));
    }, theme);
    await page.waitForTimeout(200);
  }

  // 1. Analyze Email - Dark Mode (1280px)
  {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.goto('http://localhost:5173/analyze/email', { waitUntil: 'networkidle' });
    await setTheme(page, 'dark');
    await capture(page, 'Analyze Email Dark', '01_analyze_email_dark_1280px.png');
    await page.close();
  }

  // 2. Analyze Email - Light Mode (1280px)
  {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.goto('http://localhost:5173/analyze/email', { waitUntil: 'networkidle' });
    await setTheme(page, 'light');
    await capture(page, 'Analyze Email Light', '02_analyze_email_light_1280px.png');
    await page.close();
  }

  // 3. Analyze Email - 320px Mobile
  {
    const page = await browser.newPage({ viewport: { width: 320, height: 800 } });
    await page.goto('http://localhost:5173/analyze/email', { waitUntil: 'networkidle' });
    await setTheme(page, 'dark');
    await capture(page, 'Analyze Email 320px', '03_analyze_email_mobile_320px.png');
    await page.close();
  }

  // 4. Six States on /analyze/email (1280px)
  const states = ['loading', 'empty', 'partial', 'error', 'stale', 'demo'];
  for (const st of states) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.goto(`http://localhost:5173/analyze/email?state=${st}`, { waitUntil: 'networkidle' });
    await setTheme(page, 'dark');
    await capture(page, `Analyze Email State ${st}`, `04_analyze_state_${st}.png`);
    await page.close();
  }

  // 5. Phishing Report Page (scan_345e55d15b39) - Dark Mode 1280px (Technical View)
  {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    await page.goto(`http://localhost:5173/scans/${phishScanId}`, { waitUntil: 'networkidle' });
    await setTheme(page, 'dark');
    // Switch to Technical Evidence view
    const techBtn = page.getByRole('button', { name: /Technical Evidence/i });
    if (await techBtn.isVisible()) {
      await techBtn.click();
      await page.waitForTimeout(300);
    }
    await capture(page, 'Phishing Report Technical Dark', '05_phishing_report_technical_dark_1280px.png');
    await page.close();
  }

  // 6. Phishing Report Page - Light Mode 1280px (Technical View)
  {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    await page.goto(`http://localhost:5173/scans/${phishScanId}`, { waitUntil: 'networkidle' });
    await setTheme(page, 'light');
    const techBtn = page.getByRole('button', { name: /Technical Evidence/i });
    if (await techBtn.isVisible()) {
      await techBtn.click();
      await page.waitForTimeout(300);
    }
    await capture(page, 'Phishing Report Technical Light', '06_phishing_report_technical_light_1280px.png');
    await page.close();
  }

  // 7. Phishing Report Page - Plain English View
  {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    await page.goto(`http://localhost:5173/scans/${phishScanId}`, { waitUntil: 'networkidle' });
    await setTheme(page, 'dark');
    const plainBtn = page.getByRole('button', { name: /Plain English/i });
    if (await plainBtn.isVisible()) {
      await plainBtn.click();
      await page.waitForTimeout(300);
    }
    await capture(page, 'Phishing Report Plain English', '07_phishing_report_plain_dark_1280px.png');
    await page.close();
  }

  // 8. Phishing Report Page - 320px Mobile
  {
    const page = await browser.newPage({ viewport: { width: 320, height: 900 } });
    await page.goto(`http://localhost:5173/scans/${phishScanId}`, { waitUntil: 'networkidle' });
    await setTheme(page, 'dark');
    await capture(page, 'Phishing Report Mobile 320px', '08_phishing_report_mobile_320px.png');
    await page.close();
  }

  // 9. Tracking Pixel Report Page (scan_c179a0d8b609) - Showing Sanitized Body
  {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    await page.goto(`http://localhost:5173/scans/${trackingScanId}`, { waitUntil: 'networkidle' });
    await setTheme(page, 'dark');
    await capture(page, 'Tracking Pixel Sanitized Report', '09_tracking_pixel_sanitized_report_1280px.png');
    await page.close();
  }

  await browser.close();
  console.log('All screenshots captured successfully!');
}

run().catch((err) => {
  console.error('Error capturing screenshots:', err);
  process.exit(1);
});
