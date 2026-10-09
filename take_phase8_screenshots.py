import os
import time
from playwright.sync_api import sync_playwright

OUT_DIR = "/home/ankitdey/Documents/hackathon/threatlens/screenshots"
ARTIFACT_DIR = "/home/ankitdey/.gemini/antigravity-ide/brain/6359de4f-b8ba-4ed7-a08a-12a4dca61657/screenshots"

os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(ARTIFACT_DIR, exist_ok=True)

SCAN_ID = "scan_e75653446809"
BASE_URL = f"http://localhost:5173/scans/{SCAN_ID}?view=technical"

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        viewports = [
            ("1280px", 1280, 1000),
            ("320px", 320, 900),
        ]
        
        themes = ["dark", "light"]
        
        for vp_name, width, height in viewports:
            for theme in themes:
                print(f"--- Processing {vp_name} {theme} ---")
                context = browser.new_context(viewport={"width": width, "height": height})
                page = context.new_page()
                
                # Navigate to email technical view
                page.goto(BASE_URL, wait_until="networkidle")
                
                # Apply theme
                page.evaluate(f"""(t) => {{
                    document.documentElement.setAttribute('data-theme', t);
                    localStorage.setItem('threatlens_theme', JSON.stringify(t));
                }}""", theme)
                page.wait_for_timeout(400)
                
                # 1. Full page email report with GeoPanel visible
                fname_full = f"email_report_geopanel_{theme}_{vp_name}.png"
                out_path = os.path.join(OUT_DIR, fname_full)
                page.screenshot(path=out_path, full_page=True)
                os.system(f"cp '{out_path}' '{os.path.join(ARTIFACT_DIR, fname_full)}'")
                print(f"Saved: {fname_full}")
                
                # 2. Score breakdown element screenshot showing GEOLOCATION group
                score_bar = page.locator("[data-group-id='GEOLOCATION']")
                if score_bar.count() > 0:
                    # Hover over GEOLOCATION to highlight
                    score_bar.hover()
                    page.wait_for_timeout(200)
                    fname_score = f"score_breakdown_geolocation_{theme}_{vp_name}.png"
                    out_score = os.path.join(OUT_DIR, fname_score)
                    score_container = page.locator("#score-breakdown-container")
                    if score_container.count() > 0:
                        score_container.screenshot(path=out_score)
                    else:
                        page.screenshot(path=out_score)
                    os.system(f"cp '{out_score}' '{os.path.join(ARTIFACT_DIR, fname_score)}'")
                    print(f"Saved: {fname_score}")

                # 3. WorldMapMarker rendering screenshot
                map_marker = page.locator("[role='region'][aria-label*='World map']")
                if map_marker.count() > 0:
                    fname_map = f"worldmap_marker_{theme}_{vp_name}.png"
                    out_map = os.path.join(OUT_DIR, fname_map)
                    map_marker.first.screenshot(path=out_map)
                    os.system(f"cp '{out_map}' '{os.path.join(ARTIFACT_DIR, fname_map)}'")
                    print(f"Saved: {fname_map}")

                # 4. DetailDrawer opened from an IP pivot
                pivot_buttons = page.locator("button:has-text('Pivot IP')")
                if pivot_buttons.count() > 0:
                    pivot_buttons.first.click()
                    page.wait_for_timeout(600)
                    fname_drawer = f"detail_drawer_ip_pivot_{theme}_{vp_name}.png"
                    out_drawer = os.path.join(OUT_DIR, fname_drawer)
                    page.screenshot(path=out_drawer, full_page=True)
                    os.system(f"cp '{out_drawer}' '{os.path.join(ARTIFACT_DIR, fname_drawer)}'")
                    print(f"Saved: {fname_drawer}")
                else:
                    print(f"Warning: Pivot IP button not found for {vp_name} {theme}")

                page.close()
                context.close()
        
        browser.close()
        print("All Phase 8 screenshots captured successfully!")

if __name__ == "__main__":
    run()
