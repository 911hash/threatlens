#!/usr/bin/env bash
set -e

CHROME="/home/ankitdey/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome"
OUT_DIR="/home/ankitdey/Documents/hackathon/threatlens/screenshots"
ARTIFACT_DIR="/home/ankitdey/.gemini/antigravity-ide/brain/3752bfbd-e9a5-4aa2-8f4c-b2efeb53103f/screenshots"

mkdir -p "$OUT_DIR"
mkdir -p "$ARTIFACT_DIR"

PHISH_ID="scan_81eca3d7d111"
PIXEL_ID="scan_354e80e629cc"

capture() {
  local filename="$1"
  local url="$2"
  local width="$3"
  local height="$4"
  echo "Capturing $filename ($width x $height) from $url..."
  "$CHROME" \
    --headless=new \
    --disable-gpu \
    --no-sandbox \
    --window-size="${width},${height}" \
    --virtual-time-budget=3500 \
    --screenshot="${OUT_DIR}/${filename}" \
    "$url" > /dev/null 2>&1
  cp "${OUT_DIR}/${filename}" "${ARTIFACT_DIR}/${filename}"
}

echo "=== 1. /analyze/email 1280px Desktop Screenshots ==="
capture "01_analyze_email_default_dark_1280px.png" "http://localhost:5173/analyze/email?theme=dark" 1280 1000
capture "02_analyze_email_default_light_1280px.png" "http://localhost:5173/analyze/email?theme=light" 1280 1000
capture "03_analyze_email_loading_dark_1280px.png" "http://localhost:5173/analyze/email?theme=dark&state=loading" 1280 900
capture "04_analyze_email_loading_light_1280px.png" "http://localhost:5173/analyze/email?theme=light&state=loading" 1280 900
capture "05_analyze_email_empty_dark_1280px.png" "http://localhost:5173/analyze/email?theme=dark&state=empty" 1280 900
capture "06_analyze_email_empty_light_1280px.png" "http://localhost:5173/analyze/email?theme=light&state=empty" 1280 900
capture "07_analyze_email_partial_dark_1280px.png" "http://localhost:5173/analyze/email?theme=dark&state=partial" 1280 900
capture "08_analyze_email_partial_light_1280px.png" "http://localhost:5173/analyze/email?theme=light&state=partial" 1280 900
capture "09_analyze_email_error_dark_1280px.png" "http://localhost:5173/analyze/email?theme=dark&state=error" 1280 900
capture "10_analyze_email_error_light_1280px.png" "http://localhost:5173/analyze/email?theme=light&state=error" 1280 900
capture "11_analyze_email_stale_dark_1280px.png" "http://localhost:5173/analyze/email?theme=dark&state=stale" 1280 900
capture "12_analyze_email_stale_light_1280px.png" "http://localhost:5173/analyze/email?theme=light&state=stale" 1280 900
capture "13_analyze_email_demo_dark_1280px.png" "http://localhost:5173/analyze/email?theme=dark&state=demo" 1280 1000
capture "14_analyze_email_demo_light_1280px.png" "http://localhost:5173/analyze/email?theme=light&state=demo" 1280 1000

echo "=== 2. /analyze/email 320px Mobile Screenshots ==="
capture "15_analyze_email_default_dark_320px.png" "http://localhost:5173/analyze/email?theme=dark" 320 900
capture "16_analyze_email_default_light_320px.png" "http://localhost:5173/analyze/email?theme=light" 320 900
capture "17_analyze_email_loading_dark_320px.png" "http://localhost:5173/analyze/email?theme=dark&state=loading" 320 800
capture "18_analyze_email_loading_light_320px.png" "http://localhost:5173/analyze/email?theme=light&state=loading" 320 800
capture "19_analyze_email_empty_dark_320px.png" "http://localhost:5173/analyze/email?theme=dark&state=empty" 320 800
capture "20_analyze_email_empty_light_320px.png" "http://localhost:5173/analyze/email?theme=light&state=empty" 320 800
capture "21_analyze_email_partial_dark_320px.png" "http://localhost:5173/analyze/email?theme=dark&state=partial" 320 800
capture "22_analyze_email_partial_light_320px.png" "http://localhost:5173/analyze/email?theme=light&state=partial" 320 800
capture "23_analyze_email_error_dark_320px.png" "http://localhost:5173/analyze/email?theme=dark&state=error" 320 800
capture "24_analyze_email_error_light_320px.png" "http://localhost:5173/analyze/email?theme=light&state=error" 320 800
capture "25_analyze_email_stale_dark_320px.png" "http://localhost:5173/analyze/email?theme=dark&state=stale" 320 800
capture "26_analyze_email_stale_light_320px.png" "http://localhost:5173/analyze/email?theme=light&state=stale" 320 800
capture "27_analyze_email_demo_dark_320px.png" "http://localhost:5173/analyze/email?theme=dark&state=demo" 320 900
capture "28_analyze_email_demo_light_320px.png" "http://localhost:5173/analyze/email?theme=light&state=demo" 320 900

echo "=== 3. Phishing Report Showing AuthResultsPanel, HeaderChainPanel, AttachmentList, SanitizedBodyViewer ==="
capture "29_phishing_report_dark_1280px.png" "http://localhost:5173/scans/${PHISH_ID}?theme=dark&view=technical" 1280 2600
capture "30_phishing_report_light_1280px.png" "http://localhost:5173/scans/${PHISH_ID}?theme=light&view=technical" 1280 2600
capture "31_phishing_report_plain_dark_1280px.png" "http://localhost:5173/scans/${PHISH_ID}?theme=dark&view=plain" 1280 2200
capture "32_phishing_report_dark_320px.png" "http://localhost:5173/scans/${PHISH_ID}?theme=dark&view=technical" 320 3000

echo "=== 4. Tracking-Pixel Report Showing Sanitized Body without Images ==="
capture "33_tracking_pixel_report_dark_1280px.png" "http://localhost:5173/scans/${PIXEL_ID}?theme=dark&view=technical" 1280 2200
capture "34_tracking_pixel_report_light_1280px.png" "http://localhost:5173/scans/${PIXEL_ID}?theme=light&view=technical" 1280 2200
capture "35_tracking_pixel_report_dark_320px.png" "http://localhost:5173/scans/${PIXEL_ID}?theme=dark&view=technical" 320 2600

echo "ALL SCREENSHOTS CAPTURED SUCCESSFULLY!"
