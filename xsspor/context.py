"""Context detection for reflected XSS."""

from __future__ import annotations

import re
from typing import Optional


CONTEXT_HTML_BODY = "html_body"
CONTEXT_SCRIPT = "script"
CONTEXT_ATTRIBUTE = "attribute"
CONTEXT_HREF = "href"
CONTEXT_SRC = "src"
CONTEXT_EVENT = "event"
CONTEXT_COMMENT = "comment"
CONTEXT_UNKNOWN = "unknown"


def detect_context(html: str, marker: str) -> str:
    """
    Detect reflection context around `marker` in HTML/JS response body.

    Returns one of: html_body, script, attribute, href, src, event, comment, unknown.
    """
    if not html or not marker:
        return CONTEXT_UNKNOWN

    idx = html.find(marker)
    if idx == -1:
        # try case-insensitive
        lower_html = html.lower()
        lower_marker = marker.lower()
        idx = lower_html.find(lower_marker)
        if idx == -1:
            return CONTEXT_UNKNOWN

    window = html[max(0, idx - 250) : idx]

    if re.search(r"<!--[^>]*$", window):
        return CONTEXT_COMMENT
    if re.search(r"<script[^>]*>[^<]*$", window, re.I):
        return CONTEXT_SCRIPT
    if re.search(r"""on\w+\s*=\s*['"][^'"]*$""", window, re.I):
        return CONTEXT_EVENT
    if re.search(r"""href\s*=\s*['"][^'"]*$""", window, re.I):
        return CONTEXT_HREF
    if re.search(r"""src\s*=\s*['"][^'"]*$""", window, re.I):
        return CONTEXT_SRC
    if re.search(r"""<\w+[^>]*\s[\w:-]+\s*=\s*['"][^'"]*$""", window, re.I):
        return CONTEXT_ATTRIBUTE
    if re.search(r"<[^>]*$", window):
        return CONTEXT_ATTRIBUTE
    return CONTEXT_HTML_BODY


def severity_for(
    context: str,
    reflection: str,
    confirmed: Optional[bool] = None,
) -> str:
    """
    Map context + reflection quality + browser confirmation to severity.

    CRITICAL — browser confirmed execution
    HIGH     — script / event context with strong reflection
    MEDIUM   — html_body / attribute / href / src with reflection
    LOW      — partial reflection or weak context
    INFO     — no useful reflection
    """
    if confirmed is True:
        return "CRITICAL"

    if reflection == "none":
        return "INFO"

    if context in (CONTEXT_SCRIPT, CONTEXT_EVENT) and reflection in (
        "verbatim",
        "encoded",
    ):
        return "HIGH"

    if context in (
        CONTEXT_HTML_BODY,
        CONTEXT_ATTRIBUTE,
        CONTEXT_HREF,
        CONTEXT_SRC,
    ) and reflection in ("verbatim", "encoded"):
        return "MEDIUM"

    if reflection == "partial":
        return "LOW"

    if context == CONTEXT_COMMENT:
        return "LOW"

    return "INFO"


def context_to_categories(context: str) -> list[str]:
    """Suggest payload categories that match a detected context."""
    mapping = {
        CONTEXT_SCRIPT: ["js_context", "waf_bypass"],
        CONTEXT_EVENT: ["attribute_breakout", "js_context", "waf_bypass"],
        CONTEXT_ATTRIBUTE: ["attribute_breakout", "html_body", "waf_bypass"],
        CONTEXT_HREF: ["href_context", "waf_bypass"],
        CONTEXT_SRC: ["href_context", "waf_bypass"],
        CONTEXT_HTML_BODY: ["html_body", "waf_bypass"],
        CONTEXT_COMMENT: ["html_body", "waf_bypass"],
        CONTEXT_UNKNOWN: ["html_body", "attribute_breakout", "js_context", "href_context"],
    }
    return mapping.get(context, ["html_body"])
