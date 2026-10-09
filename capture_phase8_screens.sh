#!/usr/bin/env bash
set -e

CHROME="/home/ankitdey/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome"
OUT_DIR="/home/ankitdey/Documents/hackathon/threatlens/screenshots"
ARTIFACT_DIR="/home/ankitdey/.gemini/antigravity-ide/brain/3752bfbd-e9a5-4aa2-8f4c-b2efeb53103f/screenshots"

mkdir -p "$OUT_DIR"
mkdir -p "$ARTIFACT_DIR"

echo "Uploading email_multi_hop_tor.eml to get fresh scan ID..."
SCAN_RESPONSE=$(curl -s -X POST http://127.0.0.1:8000/api/analyze/email \
  -F "file=@backend/tests/fixtures/email_multi_hop_tor.eml" \
  -F "privacy_mode=full")
SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.id')
echo "Using active Scan ID for screenshots: $SCAN_ID"

capture() {
  local filename="$1"
  local url="$2"
  local width="$3"
  local height="$4"
  echo "Capturing $filename ($width x $height)..."
  "$CHROME" \
    --headless=new \
    --disable-gpu \
    --no-sandbox \
    --window-size="${width},${height}" \
    --virtual-time-budget=4000 \
    --screenshot="${OUT_DIR}/${filename}" \
    "$url" > /dev/null 2>&1
  cp "${OUT_DIR}/${filename}" "${ARTIFACT_DIR}/${filename}"
  echo "Saved: ${OUT_DIR}/${filename}"
}

echo "=== 1. Email Report with GeoPanel Visible (1280px Desktop) ==="
capture "email_report_geopanel_dark_1280px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=dark&view=technical" 1280 2000
capture "email_report_geopanel_light_1280px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=light&view=technical" 1280 2000

echo "=== 2. Email Report with GeoPanel Visible (320px Mobile) ==="
capture "email_report_geopanel_dark_320px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=dark&view=technical" 320 2800
capture "email_report_geopanel_light_320px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=light&view=technical" 320 2800

echo "=== 3. WorldMapMarker Rendering Correctly (1280px Desktop) ==="
capture "worldmap_marker_dark_1280px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=dark&view=plain" 1280 1400
capture "worldmap_marker_light_1280px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=light&view=plain" 1280 1400

echo "=== 4. WorldMapMarker Rendering Correctly (320px Mobile - Zero Overflow) ==="
capture "worldmap_marker_dark_320px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=dark&view=plain" 320 1600
capture "worldmap_marker_light_320px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=light&view=plain" 320 1600

echo "=== 5. Score Breakdown Showing GEOLOCATION Group (1280px Desktop) ==="
capture "score_breakdown_geolocation_dark_1280px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=dark&view=technical" 1280 1200
capture "score_breakdown_geolocation_light_1280px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=light&view=technical" 1280 1200

echo "=== 6. Score Breakdown Showing GEOLOCATION Group (320px Mobile) ==="
capture "score_breakdown_geolocation_dark_320px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=dark&view=technical" 320 1200
capture "score_breakdown_geolocation_light_320px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=light&view=technical" 320 1200

echo "=== 7. DetailDrawer Opened from IP Pivot (1280px Desktop) ==="
capture "detail_drawer_ip_pivot_dark_1280px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=dark&view=technical&pivot=true" 1280 1400
capture "detail_drawer_ip_pivot_light_1280px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=light&view=technical&pivot=true" 1280 1400

echo "=== 8. DetailDrawer Opened from IP Pivot (320px Mobile) ==="
capture "detail_drawer_ip_pivot_dark_320px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=dark&view=technical&pivot=true" 320 1400
capture "detail_drawer_ip_pivot_light_320px.png" "http://localhost:5173/scans/${SCAN_ID}?theme=light&view=technical&pivot=true" 320 1400

echo "=== ALL PHASE 8 SCREENSHOTS COMPLETED! ==="
