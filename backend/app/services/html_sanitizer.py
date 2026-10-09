"""
HTML Email Sanitizer Service.

Safely sanitizes untrusted HTML email bodies before browser rendering.
Enforces security constraints:
- Strips <script>, <iframe>, <object>, <embed>, <link>, and all active content.
- Strips remote images and tracking pixels to prevent read-receipt/IP leakage.
- Strips external CSS stylesheets and @import / url(...) background references.
- Preserves layout structure, safe text formatting, and safe inline styles.
- Returns a clean HTML string suitable for rendering in a sandboxed iframe.
"""

import re
from typing import Optional
import bleach


class SafeCSSSanitizer:
    """
    Sanitizes inline CSS declarations.
    Allows safe presentation properties while eliminating external network triggers
    such as url(), @import, expression(), and javascript: schemes.
    """

    ALLOWED_PROPERTIES = {
        "color",
        "background-color",
        "font-size",
        "font-family",
        "font-weight",
        "font-style",
        "text-align",
        "text-decoration",
        "line-height",
        "letter-spacing",
        "margin",
        "margin-top",
        "margin-bottom",
        "margin-left",
        "margin-right",
        "padding",
        "padding-top",
        "padding-bottom",
        "padding-left",
        "padding-right",
        "border",
        "border-top",
        "border-bottom",
        "border-left",
        "border-right",
        "border-width",
        "border-style",
        "border-color",
        "border-radius",
        "width",
        "min-width",
        "max-width",
        "height",
        "min-height",
        "max-height",
        "display",
        "vertical-align",
        "word-break",
        "word-wrap",
        "white-space",
    }

    def sanitize_css(self, style_str: str) -> str:
        if not style_str:
            return ""

        safe_rules = []
        for decl in style_str.split(";"):
            decl = decl.strip()
            if not decl or ":" not in decl:
                continue

            prop, val = decl.split(":", 1)
            prop = prop.strip().lower()
            val = val.strip()

            if prop in self.ALLOWED_PROPERTIES:
                # Disallow network triggers and execution vectors
                if not re.search(
                    r"url\s*\(|expression\s*\(|javascript\s*:|@import|behavior\s*:",
                    val,
                    re.IGNORECASE,
                ):
                    safe_rules.append(f"{prop}: {val}")

        return "; ".join(safe_rules)


ALLOWED_TAGS = [
    "a",
    "b",
    "blockquote",
    "br",
    "code",
    "div",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "s",
    "small",
    "span",
    "strike",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "u",
    "ul",
]

ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "target", "rel"],
    "*": ["style", "class", "align", "valign", "width", "height", "colspan", "rowspan"],
}


def sanitize_html(raw_html: Optional[str]) -> str:
    """
    Sanitize raw HTML email body.
    Removes executable scripts, iframes, remote images, and tracking pixels.
    """
    if not raw_html or not raw_html.strip():
        return ""

    content = raw_html

    # 1. Remove dangerous blocks and their contents completely
    content = re.sub(r"(?is)<script\b[^>]*>.*?</script>", "", content)
    content = re.sub(r"(?is)<iframe\b[^>]*>.*?</iframe>", "", content)
    content = re.sub(r"(?is)<style\b[^>]*>.*?</style>", "", content)
    content = re.sub(r"(?is)<object\b[^>]*>.*?</object>", "", content)
    content = re.sub(r"(?is)<embed\b[^>]*>.*?</embed>", "", content)
    content = re.sub(r"(?is)<applet\b[^>]*>.*?</applet>", "", content)

    # 2. Strip external stylesheet links and meta tags
    content = re.sub(r"(?is)<link\b[^>]*>", "", content)
    content = re.sub(r"(?is)<meta\b[^>]*>", "", content)

    # 3. Strip all images (remote images, tracking pixels 1x1, web beacons)
    # This prevents any read receipts or external network leaks
    content = re.sub(r"(?is)<img\b[^>]*>", "", content)

    # 4. Strip base tags which could redirect relative links
    content = re.sub(r"(?is)<base\b[^>]*>", "", content)

    # 5. Bleach sanitization pass
    css_sanitizer = SafeCSSSanitizer()
    cleaned = bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        css_sanitizer=css_sanitizer,
        strip=True,
    )

    # 6. Ensure links have safe target and rel
    def link_callback(attrs, new=False):
        href = attrs.get((None, "href"), "")
        if href.startswith("javascript:") or href.startswith("data:"):
            return None
        attrs[(None, "target")] = "_blank"
        attrs[(None, "rel")] = "noopener noreferrer"
        return attrs

    cleaned = bleach.linkify(cleaned, callbacks=[link_callback], skip_tags=["pre", "code"])

    return cleaned.strip()
