"""Executive-summary report (one-slide HTML) for an elevation request analysis."""

from __future__ import annotations

import html
import re

from .analysis import FAIL, INFO, PASS, REVIEW, Analysis

E = html.escape

ICONS = {
    "tools": '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z"/>',
    "shield": '<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/><path d="M12 7v10" opacity=".55"/>',
    "clipboard": '<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4h6v3H9z"/><path d="m9 13 2 2 4-4"/>',
    "chip": '<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v3M14 3v3M10 18v3M14 18v3M3 10h3M3 14h3M18 10h3M18 14h3"/>',
    "warn": '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>',
    "review": '<path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/><path d="M12 8v4l3 2"/>',
}
MARK = {PASS: ("pass", "&#10003;"), REVIEW: ("review", ""), FAIL: ("fail", "&#10005;"), INFO: ("info", "i")}


def _icon(name: str, cls: str = "") -> str:
    return (f'<svg class="ic {cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS[name]}</svg>')


def _first_sentence(s: str, limit: int = 150) -> str:
    s = re.sub(r"\s+https?://\S+", "", s or "").strip()
    m = re.match(r"(.+?[.;])(\s|$)", s)
    out = m.group(1) if m else s
    return out if len(out) <= limit else out[: limit - 1].rstrip() + "…"


def _gb(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ""
    return f"{n / 1e9:.1f} GB" if n >= 1e9 else f"{n / 1e6:.0f} MB" if n >= 1e6 else f"{n / 1e3:.0f} KB"


def _cert_date(s: str | None) -> str:
    m = re.match(r"(\d+)/(\d+)/(\d{4})", s or "")
    if not m:
        return s or "unknown"
    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
    return f"{months[int(m.group(1)) - 1]} {int(m.group(2))}, {m.group(3)}"


def _li(kind: str, label: str, text: str) -> str:
    cls, glyph = MARK[kind]
    return (f'<li><span class="mk {cls}">{glyph}</span><span><b>{E(label)}:</b> {E(text)}</span></li>')


def _risk(a: Analysis) -> tuple[str, str]:
    reviews = [c for c in a.checks if c.result in (REVIEW, FAIL)]
    if a.verdict == "DENY":
        return "HIGH", "fail"
    if a.verdict == "APPROVE":
        return "LOW", "pass"
    if all(c.id in ("baseline", "user_installed") for c in reviews):
        return "LOW (Pending Authorization)", "review"
    return "MODERATE", "review"


def _plan(a: Analysis) -> tuple[list[str], str, str, str, str, str]:
    """Action-plan bullets, recommendation label, banner headline, banner text, pill, tone."""
    s, c, r = a.software, a.context, a.recommendation
    by = {ch.id: ch for ch in a.checks}
    name = f"{s.get('product') or s.get('file_name')} {s.get('product_version') or ''}".strip()
    one_time = not r.create_rule
    items: list[str] = []

    if a.verdict == "DENY":
        items.append(_li(PASS, "Deny the Request", "Deny in AutoElevate with the reason recorded; no rule of any kind."))
    elif one_time:
        items.append(_li(PASS, "One-Time Elevation", "Approve this launch only. No standing rule, since it is an installer "
                         "or a binary that must never be ruled."))
    else:
        items.append(_li(PASS, f"{(r.rule_level or 'computer').title()}-Level Rule",
                         f"Rule scoped to {c['computer']} only, matched by file hash. Widen only when the baseline names more users."))

    b = by.get("baseline")
    if b and b.result == PASS:
        items.append(_li(PASS, "Approved Baseline", f"Already on the {c['company']} approved software list (CM.L2-3.4.8)."))
    elif a.verdict != "DENY":
        items.append(_li(PASS, "Baseline Entry", f"Get {c['company']} sign-off and add it to the client's approved "
                         "software list so the next request passes 3.4.8."))

    vt = by.get("malware_scan")
    if vt and vt.result == INFO and a.verdict != "DENY":
        items.append(_li(PASS, "Endpoint Protection", "Confirm Bitdefender/EDR shows the file clean; VirusTotal isn't configured."))
    cve = by.get("cve_exposure")
    if cve and cve.result in (REVIEW, FAIL):
        items.append(_li(PASS, "Patched Release", "Have the user install the vendor's current release instead of this version."))
    priv = by.get("privileged_binary")
    if priv and priv.result != PASS:
        items.append(_li(PASS, "Supervised Use Only", "Technician confirms the task; never create a standing rule for this binary."))
    items.append(_li(PASS, "Change Record", f"Post the analysis to CW ticket #{c['ticket']} (CM.L2-3.4.3, 3.4.4, AU.L2-3.3.1)."))

    hard = [ch.title for ch in a.checks if ch.result == FAIL and ch.hard]
    open_items = [ch.title.lower() for ch in a.checks if ch.result in (REVIEW, FAIL)]
    if a.verdict == "DENY":
        rec, tone, pill = "DENY", "fail", "DENY RECOMMENDED"
        head = f"Deny {name}"
        text = f"Blocked by: {'; '.join(hard).lower()}."
    elif a.verdict == "APPROVE":
        rec = "APPROVE ONE-TIME" if one_time else f"APPROVE · {(r.rule_level or 'computer').upper()} RULE"
        tone, pill = "pass", "READY FOR APPROVAL"
        head = f"Approve {name}" + (" (One-Time)" if one_time else f" with a {r.rule_level}-level rule")
        text = "Every check passed; the narrowest scope is applied and the decision is logged to the ticket."
    else:
        tone = "review"
        baseline_only = _risk(a)[0].startswith("LOW")
        if baseline_only:
            rec, pill = "AUTHORIZE & APPROVE ONE-TIME" if one_time else "AUTHORIZE & APPROVE", "NEEDS AUTHORIZATION"
            head = f"Authorize {name} for {c['company']}"
            text = ("Software checks are clean. Approving adds it to the client's authorized software "
                    "(permit-by-exception, CM.L2-3.4.8).")
        else:
            rec, pill = "ESCALATE FOR REVIEW", "REVIEW REQUIRED"
            head = f"Review {name} Before Approving"
            text = f"Open items: {'; '.join(open_items)}."
    return items, rec, head, text, pill, tone


def render_html(a: Analysis, standalone: bool = True) -> str:
    s, c = a.software, a.context
    name = f"{s.get('product') or s.get('file_name')} {s.get('product_version') or ''}".strip()
    risk, risk_tone = _risk(a)
    plan, rec, head, banner, pill, tone = _plan(a)

    path = s.get("file_path") or ""
    origin = ("the user's Downloads folder" if "\\downloads\\" in path.lower() else
              "a network share" if path.startswith("\\\\") else
              "a user profile folder" if "\\users\\" in path.lower() else "a protected install path")
    signer_ok = s.get("signed") and s.get("signature_verified")
    issuer = re.sub(r"\s+(RSA|SHA|CA\d|20\d\d).*$", "", s.get("issuer") or "")
    pkg = [
        _li(PASS, "Product", f"{name} from {s.get('vendor') or 'unknown vendor'} ({s.get('file_name')}"
            + (f", {_gb(s.get('size_bytes'))}" if s.get("size_bytes") else "") + ")."),
        _li(PASS if signer_ok else FAIL, "Publisher",
            f"Signed by {s.get('signer')} via {issuer}; certificate valid to {_cert_date(s.get('cert_valid_to'))}."
            if s.get("signed") else "Unsigned; the publisher can't be verified."),
        _li(PASS, "Request", f"{c.get('user')} on {c.get('computer')}, {c.get('requested_elevation') or 'admin'} "
            f"elevation, launched from {origin}."),
    ]
    kind = "One-time installer" if any(m in (s.get("file_name") or "").lower() + (s.get("description") or "").lower()
                                       for m in ("setup", "install", ".msi")) else "Recurring application"

    order = {FAIL: 0, REVIEW: 1, PASS: 2, INFO: 3}
    checks = sorted([ch for ch in a.checks if ch.id != "change_record"], key=lambda ch: order[ch.result])
    sec = []
    for ch in checks[:5]:
        pr = f" ({ch.practices[0].split('-', 1)[1]})" if ch.practices else ""
        sec.append(_li(ch.result, f"{ch.title}{pr}", _first_sentence(ch.detail) or ch.title + "."))

    def card(eyebrow, title, icon, items, k, v, vtone, extra_cls=""):
        return f"""
      <section class="card {extra_cls}">
        <header class="card-h">{_icon(icon, 'tile')}<div><p class="eyebrow">{E(eyebrow)}</p><h2>{E(title)}</h2></div></header>
        <ul>{''.join(items)}</ul>
        <footer class="card-f"><span>{E(k)}</span><strong class="{vtone}">{E(v)}</strong></footer>
      </section>"""

    body = f"""<title>{E(name)} Review</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Manrope:wght@500;600;700;800&family=JetBrains+Mono:wght@500&display=swap">
<style>
/* One dark slide: header row, three equal cards, action banner. Dark-first, light mirror. */
:root {{
  --page:#070b14; --slide:#0c1322; --card:#0f1829; --line:#1f2b40; --fg:#e7edf7; --muted:#93a1b8;
  --accent:#6aa8ff; --pass:#3ddc97; --review:#f5a524; --fail:#ff6b6b; --info:#7cc4ff;
  --glow:rgba(245,165,36,.07); --shadow:0 24px 60px rgba(0,0,0,.45);
  --display:"Manrope", system-ui, "Segoe UI", sans-serif; --body:"Manrope", system-ui, "Segoe UI", sans-serif;
  --mono:"JetBrains Mono", ui-monospace, Consolas, monospace; color-scheme:dark;
}}
@media (prefers-color-scheme: light) {{ :root:not([data-theme="dark"]) {{
  --page:#eef1f6; --slide:#ffffff; --card:#f7f9fc; --line:#d9e0ea; --fg:#0f1a2b; --muted:#5a6a82;
  --accent:#1f62d6; --pass:#0b8a5a; --review:#b26a00; --fail:#c23434; --info:#1f6fb8;
  --glow:rgba(245,165,36,.08); --shadow:0 18px 40px rgba(15,26,43,.10); color-scheme:light; }} }}
:root[data-theme="light"] {{
  --page:#eef1f6; --slide:#ffffff; --card:#f7f9fc; --line:#d9e0ea; --fg:#0f1a2b; --muted:#5a6a82;
  --accent:#1f62d6; --pass:#0b8a5a; --review:#b26a00; --fail:#c23434; --info:#1f6fb8;
  --glow:rgba(245,165,36,.08); --shadow:0 18px 40px rgba(15,26,43,.10); color-scheme:light; }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--page); color:var(--fg); font:15px/1.5 var(--body);
  padding-block:32px; padding-left:max(16px, env(safe-area-inset-left, 0px)); padding-right:max(16px, env(safe-area-inset-right, 0px)); }}
.slide {{ max-width:1240px; margin:0 auto; background:radial-gradient(120% 80% at 85% 0%, var(--glow), transparent 60%), var(--slide);
  border:1px solid var(--line); border-radius:18px; box-shadow:var(--shadow); position:relative; overflow:hidden;
  padding:44px clamp(18px, 4vw, 52px) 36px; display:grid; gap:30px; }}
.slide::before {{ content:""; position:absolute; inset:0 0 auto; height:3px; background:linear-gradient(90deg, var(--review), var(--accent), var(--pass)); }}
.top {{ display:flex; flex-wrap:wrap; justify-content:space-between; gap:20px; align-items:flex-start }}
.top > div {{ min-width:0 }}
.badge {{ display:inline-flex; align-items:center; gap:7px; padding:4px 12px; border-radius:999px; font-size:11.5px; font-weight:800;
  letter-spacing:.12em; text-transform:uppercase; color:var(--{tone}); background:color-mix(in srgb, var(--{tone}) 12%, transparent);
  border:1px solid color-mix(in srgb, var(--{tone}) 45%, transparent) }}
.badge .ic {{ width:14px; height:14px }}
h1 {{ font:800 clamp(26px, 3.4vw, 36px)/1.15 var(--display); letter-spacing:-.02em; margin:14px 0 6px; text-wrap:balance }}
.sub {{ color:var(--muted); margin:0; max-width:70ch }}
.scope {{ text-align:right; display:grid; gap:8px; justify-items:end }}
.chip {{ display:inline-flex; align-items:center; gap:8px; padding:6px 14px; border:1px solid var(--line); border-radius:8px;
  background:var(--card); font-weight:600; font-size:14px }}
.chip .ic {{ width:16px; height:16px; color:var(--review) }}
.req {{ color:var(--accent); font-size:13px }}
.cards {{ display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:22px }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:24px 24px 18px; display:flex; flex-direction:column; gap:18px; min-width:0 }}
.card.lead {{ border-color:color-mix(in srgb, var(--{tone}) 40%, var(--line)); box-shadow:0 0 0 1px color-mix(in srgb, var(--{tone}) 12%, transparent), 0 18px 40px color-mix(in srgb, var(--{tone}) 8%, transparent) }}
.card-h {{ display:flex; gap:14px; align-items:center }}
.ic.tile {{ width:46px; height:46px; padding:11px; border-radius:10px; flex:none; color:var(--accent); background:color-mix(in srgb, var(--accent) 14%, transparent) }}
.card:nth-child(2) .ic.tile {{ color:var(--review); background:color-mix(in srgb, var(--review) 14%, transparent) }}
.card:nth-child(3) .ic.tile {{ color:var(--pass); background:color-mix(in srgb, var(--pass) 14%, transparent) }}
.eyebrow {{ margin:0; font-size:11.5px; font-weight:700; letter-spacing:.12em; color:var(--muted); text-transform:uppercase }}
h2 {{ margin:2px 0 0; font:800 19px/1.25 var(--display); letter-spacing:-.01em }}
ul {{ list-style:none; margin:0; padding:0; display:grid; gap:14px; flex:1; align-content:start }}
li {{ display:grid; grid-template-columns:18px minmax(0,1fr); gap:9px; font-size:14px; line-height:1.5; color:color-mix(in srgb, var(--fg) 86%, var(--muted)) }}
li b {{ color:var(--fg); font-weight:700 }}
.mk {{ width:16px; height:16px; margin-top:3px; border-radius:50%; display:grid; place-items:center; font-size:11px; font-weight:800; line-height:1 }}
.mk.pass {{ color:var(--pass) }} .mk.fail {{ color:var(--fail) }}
.mk.review {{ border:3.5px solid var(--review) }}
.mk.info {{ color:var(--info); border:1.5px solid var(--info); font-size:10px; font-family:Georgia, serif; font-style:italic }}
.card-f {{ display:flex; justify-content:space-between; align-items:baseline; gap:10px; flex-wrap:wrap; padding-top:14px; border-top:1px solid var(--line); font-size:13px; color:var(--muted) }}
.card-f strong {{ font-weight:800; font-size:13px; letter-spacing:.02em; text-align:right }}
.pass {{ color:var(--pass) }} .review {{ color:var(--review) }} .fail {{ color:var(--fail) }} .accent {{ color:var(--accent) }}
.hash {{ font:500 12px var(--mono); color:var(--muted); overflow-wrap:anywhere }}
.banner {{ display:flex; flex-wrap:wrap; align-items:center; gap:16px; padding:16px 22px; border:1px solid var(--line); border-radius:12px; background:var(--card) }}
.banner .ic {{ width:28px; height:28px; color:var(--{tone}); flex:none }}
.banner div {{ flex:1; min-width:220px }}
.banner strong {{ display:block; font:800 16px/1.3 var(--display) }}
.banner p {{ margin:2px 0 0; color:var(--muted); font-size:14px }}
.pill {{ padding:8px 16px; border-radius:8px; font-weight:800; font-size:13px; letter-spacing:.06em;
  background:var(--{tone}); color:var(--slide) }}
.meta {{ display:flex; flex-wrap:wrap; justify-content:space-between; gap:8px 20px; font-size:12px; color:var(--muted) }}
@media (max-width: 900px) {{ .cards {{ grid-template-columns:1fr }} .scope {{ text-align:left; justify-items:start }} }}
</style>
<main class="slide">
  <div class="top">
    <div>
      <span class="badge">{_icon('review')}Pre-Approval Security Review</span>
      <h1>Executive Summary: {E(name)}</h1>
      <p class="sub">AutoElevate elevation request for {E(s.get('file_name') or '')}, checked against CMMC Level 2 (NIST SP 800-171 Rev 2) before approval.</p>
    </div>
    <div class="scope">
      <span class="chip">{_icon('chip')}Scope: {E(c.get('company') or '')} | {E(c.get('computer') or '')}</span>
      <span class="req">Requester: {E(c.get('user') or 'unknown')} · CW #{E(str(c.get('ticket') or '—'))}</span>
    </div>
  </div>
  <div class="cards">
    {card('Software & Request', 'Software Package', 'tools', pkg, 'Request Type', kind, 'accent')}
    {card('NIST SP 800-171 Rev 2', 'Security Checks', 'shield', sec, 'CMMC Level 2 Risk', risk, risk_tone)}
    {card('Action Plan', 'Approval Guardrails', 'clipboard', plan, 'Recommendation', rec, tone, 'lead')}
  </div>
  <div class="banner" role="status">
    {_icon('warn')}
    <div><strong>Action Requested: {E(head)}</strong><p>{E(banner)}</p></div>
    <span class="pill">{E(pill)}</span>
  </div>
  <div class="meta">
    <span class="hash">SHA-256 {E(s.get('sha256') or 'n/a')}</span>
    <span>Request {E(a.request_id or '')} · analyzed {E(a.analyzed_at)}</span>
  </div>
</main>"""
    if standalone:
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
                + body.replace("<main", "</head><body><main", 1) + "</body></html>")
    return body
