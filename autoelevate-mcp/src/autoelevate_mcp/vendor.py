"""New vendor / product review against NIST SP 800-171 Rev 2 and NIST SP 800-53.

Controls: 800-171 3.4.6, 3.4.7, 3.4.8, 3.4.9, 3.11.1, 3.11.2, 3.13.11 and
800-53 CM-7, CM-10, SA-9, SR-3, SR-6 (config/vendor_review.yaml).

evaluate() turns an intake form plus researched facts into a pass/fail result per
control, an overall decision, approval conditions and the components most at risk.
render_vendor_html() makes the two-slide executive summary.

The facts come from research (the vendor's trust center, FedRAMP marketplace,
pricing pages). Anything left unknown is judged CONDITIONAL, never PASS.
"""

from __future__ import annotations

import html
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .analysis import ROOT, load_yaml

E = html.escape
PASS, COND, FAIL_CUI, FAIL = "PASS", "CONDITIONAL", "FAIL · CUI", "FAIL"


@dataclass
class ControlResult:
    id: str
    name: str
    criterion: str
    result: str
    finding: str


@dataclass
class VendorReview:
    vendor: str
    product: str
    purpose: str
    users: str
    decision: str            # APPROVE / CONDITIONAL / DENY
    headline: str
    pass_scope: str
    fail_scope: str
    controls: list[ControlResult]
    conditions: list[str]
    at_risk: list[str]
    profile: list[str]
    cost_label: str
    cost_value: str
    risk_label: str
    notes: list[str] = field(default_factory=list)
    analyzed_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def counts(self) -> dict[str, int]:
        out = {PASS: 0, COND: 0, FAIL_CUI: 0, FAIL: 0}
        for c in self.controls:
            out[c.result] += 1
        return out


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def _b(v: Any) -> bool | None:
    if isinstance(v, bool) or v is None:
        return v
    s = str(v).strip().lower()
    if s in ("yes", "true", "y", "1"):
        return True
    if s in ("no", "false", "n", "0"):
        return False
    return None


def evaluate(intake: dict, facts: dict, config: dict | None = None) -> VendorReview:
    """intake: vendor, product, users, licensing, cost, website, purpose.

    facts (all optional; unknown => CONDITIONAL):
      cui: yes / no / possible   - will the tool hold CUI, ITAR or controlled technical info
      deployment: saas / on_prem / desktop
      fedramp: none / in_process / moderate / high   (for the edition being bought)
      fedramp_alternative: text  - e.g. "Gov Cloud: from $64K/yr"
      fips_validated: yes / no
      certifications: [SOC 2 Type II, ISO 27001, ...]
      vendor_patches: yes / no   - vendor patches the service (SaaS)
      kev_note: text             - KEV history and whether it applies to this edition
      free_tier_limit: int, plan: str, plan_reason: str
      ai_features, public_sharing, marketplace_apps, user_installable_addons: yes / no
      can_disable_nonessential: yes / no
      sso_enforceable: yes / no, sso_requires: text (e.g. "Atlassian Guard")
      subprocessors: [AWS hosting, ...]
      hosting: text, ownership: text
      cost_estimate: text, incidents: [text], at_risk: [text], conditions: [text]
    """
    cfg = config or load_yaml(ROOT / "config" / "vendor_review.yaml")
    meta = {c["id"]: c for c in cfg["controls"]}
    cui = str(facts.get("cui", "possible")).lower()
    cui_possible = cui in ("yes", "possible", "unknown", "")
    cui_yes = cui == "yes"
    saas = str(facts.get("deployment", "saas")).lower() == "saas"
    fedramp = str(facts.get("fedramp", "none")).lower()
    fedramp_ok = fedramp in ("moderate", "high")
    fips = _b(facts.get("fips_validated"))
    certs = list(facts.get("certifications") or [])
    patches = _b(facts.get("vendor_patches"))
    ai, share = _b(facts.get("ai_features")), _b(facts.get("public_sharing"))
    apps, user_addons = _b(facts.get("marketplace_apps")), _b(facts.get("user_installable_addons"))
    can_disable = _b(facts.get("can_disable_nonessential"))
    sso, sso_req = _b(facts.get("sso_enforceable")), facts.get("sso_requires")
    subs = list(facts.get("subprocessors") or [])
    try:
        n_users = max(int(x) for x in __import__("re").findall(r"\d+", str(intake.get("users", "0"))))
    except ValueError:
        n_users = 0
    free_limit = facts.get("free_tier_limit")

    res: dict[str, tuple[str, str]] = {}
    nonessential = [n for n, on in (("AI", ai), ("apps", apps), ("public links", share)) if on]
    if nonessential:
        res["3.4.6"] = (COND, f"{_cap(', '.join(nonessential))} default on")
    else:
        res["3.4.6"] = (PASS if ai is False and share is False else COND,
                        "No nonessential features found" if ai is False and share is False else "Feature set not confirmed")
    res["3.4.7"] = ((COND, "Can be disabled by admin policy") if can_disable is not False
                    else (FAIL, "Nonessential functions can't be disabled"))
    res["3.4.8"] = (PASS, "Web app; add to approved list") if saas else (COND, "Add to allowlist by hash/publisher")
    if user_addons:
        res["3.4.9"] = (COND, "Block user Marketplace installs")
    elif user_addons is False:
        res["3.4.9"] = (PASS, "Users can't add software")
    else:
        res["3.4.9"] = (COND, "Add-on controls not confirmed")
    if cui_yes and not fedramp_ok:
        res["3.11.1"] = (FAIL, "CUI in a non-FedRAMP service")
    elif cui_possible and not fedramp_ok:
        res["3.11.1"] = (FAIL_CUI, "Unacceptable if CUI is stored")
    else:
        res["3.11.1"] = (PASS, "Documented in this review")
    if patches and certs:
        res["3.11.2"] = (PASS, f"{certs[0]}; vendor patches")
    elif patches:
        res["3.11.2"] = (COND, "Vendor patches; no audit report")
    else:
        res["3.11.2"] = (COND, "Patch process not evidenced")
    if fips or fedramp_ok:
        res["3.13.11"] = (PASS, "FIPS-validated encryption")
    elif cui_yes:
        res["3.13.11"] = (FAIL, "No FIPS-validated crypto")
    else:
        res["3.13.11"] = (FAIL_CUI, "No FIPS commitment, commercial" if fips is False else "FIPS validation not confirmed")
    res["CM-7"] = (res["3.4.7"][0] if res["3.4.6"][0] != PASS else PASS, "Same settings as 3.4.6 and 3.4.7")
    if free_limit and n_users > int(free_limit):
        res["CM-10"] = (PASS, f"{n_users} users needs {facts.get('plan', 'a paid')} plan")
    else:
        res["CM-10"] = (PASS, "Licensed seats cover all users")
    if not saas:
        res["SA-9"] = (PASS, "Not an external service")
    elif fedramp_ok:
        res["SA-9"] = (PASS, f"FedRAMP {fedramp.title()} authorized")
    elif cui_yes:
        res["SA-9"] = (FAIL, "Not FedRAMP authorized")
    else:
        res["SA-9"] = (FAIL_CUI, "Commercial cloud not authorized")
    res["SR-3"] = (COND, ", ".join(subs[:3]) if subs else "Sub-suppliers not disclosed")
    res["SR-6"] = (PASS, ", ".join(certs[:3])) if certs else (FAIL, "No independent audit reports")

    controls = [ControlResult(cid, meta[cid]["name"], meta[cid]["criterion"], *res[cid]) for cid in meta]

    hard = [c for c in controls if c.result == FAIL]
    cui_fails = [c for c in controls if c.result == FAIL_CUI]
    if hard:
        decision, headline = "DENY", f"{intake['product']}: not approved"
    elif cui_fails:
        decision, headline = "CONDITIONAL", f"{intake['product']}: approve for non-CUI work only"
    elif any(c.result == COND for c in controls):
        decision, headline = "CONDITIONAL", f"{intake['product']}: approve with conditions"
    else:
        decision, headline = "APPROVE", f"{intake['product']}: approved"

    conditions = list(facts.get("conditions") or [])
    if not conditions:
        if cui_fails:
            conditions.append("Non-CUI content only, labeled")
        if facts.get("plan"):
            conditions.append(f"{facts['plan']} plan or higher" + (" (Free fails)" if free_limit else ""))
        if sso is not False:
            conditions.append(f"{sso_req + ': ' if sso_req else ''}Entra SSO, MFA, SCIM")
        if nonessential:
            conditions.append(f"{_cap(', '.join(nonessential))} off")
        if user_addons:
            conditions.append("Admin approval for every add-on")
        conditions.append("Yearly audit-report review")

    at_risk = list(facts.get("at_risk") or [])
    if not at_risk:
        if cui_possible:
            at_risk.append("Stored content: CUI/CTI spill")
        if apps:
            at_risk.append("Marketplace apps reading content")
        if ai:
            at_risk.append("AI features sending text to LLMs")
        if sso_req:
            at_risk.append(f"Logins without {sso_req}")
        if share:
            at_risk.append("Public links, exports, downloads")

    profile = []
    if facts.get("ownership"):
        profile.append(facts["ownership"])
    if facts.get("hosting"):
        profile.append(facts["hosting"])
    if certs:
        profile.append(", ".join(certs[:3]))
    profile.append("FedRAMP: " + ({"none": "not authorized", "in_process": "in process"}.get(fedramp, fedramp.title())))
    if facts.get("fedramp_alternative"):
        profile.append(facts["fedramp_alternative"])

    pass_scope = ("All intended use" if decision == "APPROVE" else
                  "Non-CUI content with the conditions" if cui_fails else
                  "Intended use once the conditions are met" if decision == "CONDITIONAL" else "None")
    fail_scope = ("Any CUI, ITAR or controlled technical information" if cui_fails or decision == "DENY"
                  else "Use outside the approved purpose")
    risk = "High with CUI" if cui_fails else ("High" if hard else "Low" if decision == "APPROVE" else "Moderate")

    return VendorReview(
        vendor=intake.get("vendor", ""), product=intake.get("product", ""), purpose=intake.get("purpose", ""),
        users=str(intake.get("users", "")), decision=decision, headline=headline,
        pass_scope=pass_scope, fail_scope=fail_scope, controls=controls, conditions=conditions[:5],
        at_risk=at_risk[:5], profile=profile[:5], cost_label=facts.get("cost_label", "Est. cost"),
        cost_value=facts.get("cost_estimate", intake.get("cost", "")), risk_label=risk,
        notes=list(facts.get("incidents") or []) + ([facts["kev_note"]] if facts.get("kev_note") else []),
        analyzed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


# ------------------------------------------------------------------ rendering
TONE = {PASS: "pass", COND: "review", FAIL_CUI: "fail", FAIL: "fail"}


def render_vendor_html(r: VendorReview, standalone: bool = True) -> str:
    n = r.counts()
    tone = {"APPROVE": "pass", "CONDITIONAL": "review", "DENY": "fail"}[r.decision]
    li = lambda items: "".join(f"<li>{E(i)}</li>" for i in items)  # noqa: E731
    rows = "".join(
        f'<tr><td class="c">{E(c.id)} {E(c.name)}</td><td>{E(c.criterion)}</td><td>{E(c.finding)}</td>'
        f'<td class="r {TONE[c.result]}">{E(c.result)}</td></tr>' for c in r.controls)
    title = (f"Control results: {n[PASS]} pass, {n[COND]} conditional, "
             f"{n[FAIL_CUI] + n[FAIL]} fail" + (" for CUI" if n[FAIL_CUI] and not n[FAIL] else ""))
    body = f"""<title>{E(r.product)} Vendor Review</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Manrope:wght@500;600;700;800&display=swap">
<style>
/* Two 16:9 slides stacked: decision summary, then the control table. Dark-first, light mirror. */
:root {{
  --page:#070b14; --slide:#0b1220; --card:#111b2e; --line:#22304a; --fg:#e8eef7; --soft:#c9d4e4; --muted:#9aa8bf;
  --accent:#6aa8ff; --pass:#3ddc97; --review:#f5a524; --fail:#ff7a7a; --band:#0e1728;
  --font:"Manrope", system-ui, "Segoe UI", sans-serif; color-scheme:dark;
}}
@media (prefers-color-scheme: light) {{ :root:not([data-theme="dark"]) {{
  --page:#eef1f6; --slide:#ffffff; --card:#f6f8fc; --line:#d9e0ea; --fg:#0f1a2b; --soft:#33435a; --muted:#5a6a82;
  --accent:#1f62d6; --pass:#0b8a5a; --review:#a35f00; --fail:#c23434; --band:#eef2f8; color-scheme:light; }} }}
:root[data-theme="light"] {{
  --page:#eef1f6; --slide:#ffffff; --card:#f6f8fc; --line:#d9e0ea; --fg:#0f1a2b; --soft:#33435a; --muted:#5a6a82;
  --accent:#1f62d6; --pass:#0b8a5a; --review:#a35f00; --fail:#c23434; --band:#eef2f8; color-scheme:light; }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--page); color:var(--fg); font:15px/1.45 var(--font); padding-block:28px;
  padding-left:max(16px, env(safe-area-inset-left, 0px)); padding-right:max(16px, env(safe-area-inset-right, 0px)); }}
.deck {{ display:grid; gap:28px; max-width:1280px; margin:0 auto }}
.slide {{ background:var(--slide); border:1px solid var(--line); border-radius:16px; position:relative; overflow:hidden;
  padding:clamp(20px, 3.4vw, 44px) clamp(18px, 4vw, 52px); display:flex; flex-direction:column; gap:20px }}
.slide::before {{ content:""; position:absolute; inset:0 0 auto; height:4px; background:linear-gradient(90deg, var(--review), var(--accent), var(--pass)) }}
.top {{ display:flex; flex-wrap:wrap; justify-content:space-between; gap:16px; align-items:flex-start }}
.top > div {{ min-width:0; flex:1 }}
.eyebrow {{ display:inline-block; font-size:12px; font-weight:800; letter-spacing:.14em; text-transform:uppercase; color:var(--review);
  border:1px solid color-mix(in srgb, var(--review) 45%, transparent); background:color-mix(in srgb, var(--review) 12%, transparent);
  border-radius:999px; padding:4px 12px; margin:0 }}
.eyebrow.plain {{ border:0; background:none; padding:0; color:var(--accent) }}
h1, h2 {{ margin:10px 0 4px; font-weight:800; letter-spacing:-.02em; line-height:1.12; text-wrap:balance }}
h1 {{ font-size:clamp(24px, 3.2vw, 36px) }} h2 {{ font-size:clamp(20px, 2.6vw, 30px) }}
.sub {{ margin:0; color:var(--muted); max-width:75ch }}
.chip {{ border:1px solid var(--line); background:var(--card); border-radius:8px; padding:6px 12px; font-weight:600; white-space:nowrap; font-size:14px }}
.verdicts {{ display:grid; grid-template-columns:1fr 1fr; gap:14px }}
.v {{ border-radius:12px; padding:14px 18px; border:2px solid; display:grid; gap:2px }}
.v b {{ font-size:13px; letter-spacing:.12em }} .v span {{ font-size:15px }}
.v.ok {{ border-color:color-mix(in srgb, var(--pass) 60%, transparent); background:color-mix(in srgb, var(--pass) 9%, transparent) }} .v.ok b {{ color:var(--pass) }}
.v.no {{ border-color:color-mix(in srgb, var(--fail) 60%, transparent); background:color-mix(in srgb, var(--fail) 9%, transparent) }} .v.no b {{ color:var(--fail) }}
.cards {{ display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:14px; flex:1 }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px 20px; display:flex; flex-direction:column; gap:12px; min-width:0 }}
.card.lead {{ border:2px solid color-mix(in srgb, var(--{tone}) 55%, var(--line)) }}
.card h3 {{ margin:0; font-size:18px; font-weight:800 }}
.card ul {{ margin:0; padding-left:18px; display:grid; gap:6px; color:var(--soft); font-size:14.5px; flex:1; align-content:start }}
.foot {{ display:flex; justify-content:space-between; align-items:baseline; gap:8px; flex-wrap:wrap; border-top:1px solid var(--line); padding-top:10px; font-size:13px; color:var(--muted) }}
.foot strong {{ font-size:15px }}
.tbl {{ overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:12px }}
table {{ width:100%; border-collapse:collapse; font-size:14.5px; min-width:640px }}
th {{ text-align:left; color:var(--muted); font-weight:700; font-size:12px; letter-spacing:.08em; text-transform:uppercase; padding:10px 14px }}
td {{ padding:9px 14px; border-top:1px solid var(--line); color:var(--soft) }}
tr:nth-child(odd) td {{ background:var(--band) }}
td.c {{ color:var(--fg); font-weight:600 }} td.r {{ font-weight:800; white-space:nowrap }}
.pass {{ color:var(--pass) }} .review {{ color:var(--review) }} .fail {{ color:var(--fail) }} .accent {{ color:var(--accent) }}
.legend {{ margin:0; color:var(--muted); font-size:13px }}
@media (max-width: 860px) {{ .cards, .verdicts {{ grid-template-columns:1fr }} }}
</style>
<main class="deck">
<section class="slide" aria-label="Slide 1: decision">
  <div class="top">
    <div><p class="eyebrow">New Vendor Security Review</p>
      <h1>{E(r.headline)}</h1>
      <p class="sub">{E(r.vendor)} {E(r.product)} for {E(r.users)} users, assessed against NIST SP 800-171 Rev 2 and NIST SP 800-53.</p></div>
    <span class="chip">Scope: {E(r.users)} users</span>
  </div>
  <div class="verdicts">
    <div class="v ok"><b>{'APPROVE' if r.decision == 'APPROVE' else 'CONDITIONAL PASS' if r.decision == 'CONDITIONAL' else 'PASS'}</b><span>{E(r.pass_scope)}</span></div>
    <div class="v no"><b>FAIL</b><span>{E(r.fail_scope)}</span></div>
  </div>
  <div class="cards">
    <div class="card"><h3>Vendor profile</h3><ul>{li(r.profile)}</ul>
      <div class="foot"><span>{E(r.cost_label)}</span><strong class="accent">{E(r.cost_value)}</strong></div></div>
    <div class="card"><h3>Most at risk</h3><ul>{li(r.at_risk)}</ul>
      <div class="foot"><span>CMMC L2 risk</span><strong class="review">{E(r.risk_label)}</strong></div></div>
    <div class="card lead"><h3>Conditions to approve</h3><ul>{li(r.conditions)}</ul>
      <div class="foot"><span>Recommendation</span><strong class="{tone}">{E({'APPROVE': 'Approve', 'CONDITIONAL': 'Conditional approval', 'DENY': 'Do not approve'}[r.decision])}</strong></div></div>
  </div>
</section>
<section class="slide" aria-label="Slide 2: control results">
  <div><p class="eyebrow plain">NIST SP 800-171 Rev 2 · NIST SP 800-53</p><h2>{E(title)}</h2></div>
  <div class="tbl"><table>
    <tr><th>Control</th><th>Pass criterion</th><th>Finding</th><th>Result</th></tr>{rows}
  </table></div>
  <p class="legend">Conditional = passes once the approval conditions are configured. FAIL · CUI = fails only if CUI or controlled technical information is stored. Reviewed {E(r.analyzed_at[:10])}.</p>
</section>
</main>"""
    if standalone:
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
                + body.replace("<main", "</head><body><main", 1) + "</body></html>")
    return body
