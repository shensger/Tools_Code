"""CMMC Level 2 pre-approval analysis for AutoElevate elevation requests.

analyze() takes a request as returned by the AutoElevate API plus optional
context (the client's baseline, existing rules, intel lookups) and returns a
verdict with per-check results mapped to CMMC L2 / NIST 800-171 Rev 2 practices.

Verdicts:
  DENY      - a hard failure (malware detection, KEV on this version, invalid
              signature, prohibited category, standing rule for a shell/OS binary)
  ESCALATE  - something needs a human decision (not on baseline, unknown to
              VirusTotal, CVEs on this version, EOL, elevated session, etc.)
  APPROVE   - every check passed; includes the narrowest recommended scope
"""

from __future__ import annotations

import ntpath
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .intel import Intel, _norm, _cmp, parse_version

ROOT = Path(__file__).resolve().parents[2]

PASS, REVIEW, FAIL, INFO = "PASS", "REVIEW", "FAIL", "INFO"


def load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@dataclass
class Check:
    id: str
    result: str          # PASS / REVIEW / FAIL / INFO
    title: str
    detail: str
    practices: list[str] = field(default_factory=list)
    hard: bool = False   # FAIL that forces DENY (vs FAIL that only escalates)


@dataclass
class Recommendation:
    decision: str                 # approve / deny / escalate
    create_rule: bool = False
    rule_level: str | None = None
    elevation_type: str | None = None
    rationale: str = ""


@dataclass
class Analysis:
    request_id: str
    verdict: str
    framework: str
    software: dict
    context: dict
    checks: list[Check]
    recommendation: Recommendation
    analyzed_at: str

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------- helpers
def _get(d: Any, *path: str, default: Any = None) -> Any:
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p)
    return default if d is None else d


def _contains_any(hay: str, needles: list[str]) -> str | None:
    h = hay.lower()
    for n in needles:
        n = str(n).lower()
        if re.search(r"(?<![a-z0-9])" + re.escape(n.strip()) + r"(?![a-z0-9])", h) if n.strip().isalnum() else n in h:
            return n.strip()
    return None


def _parse_cert_date(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def _cn(dn: str | None) -> str:
    m = re.search(r"CN=([^,]+)", dn or "")
    return m.group(1).strip().strip('"') if m else (dn or "")


def extract_software(req: dict) -> dict:
    t = _get(req, "event", "data", "trigger", default={})
    cert = t.get("publisherCertInfo") or {}
    hashes = t.get("fileHashes") or {}
    return {
        "file_name": t.get("fileName") or ntpath.basename(t.get("filePath") or ""),
        "file_path": t.get("filePath"),
        "arguments": t.get("arguments"),
        "description": t.get("fileDescription") or t.get("uacTitle"),
        "product": t.get("productName"),
        "product_version": t.get("productVersion"),
        "file_version": t.get("fileVersion"),
        "vendor": t.get("productCompany"),
        "sha256": hashes.get("SHA256"),
        "md5": hashes.get("MD5") or t.get("fileHash"),
        "size_bytes": t.get("fileSize"),
        "signed": t.get("isSigned"),
        "signature_verified": t.get("isPublisherCertVerified"),
        "signer": _cn(cert.get("subject")),
        "issuer": _cn(cert.get("issuer")),
        "cert_self_signed": cert.get("isSelfSigned"),
        "cert_valid_to": cert.get("validTo"),
        "cert_thumbprint": cert.get("thumbprint"),
        "cert_error": cert.get("verificationErrorMessage"),
    }


def match_baseline(sw: dict, baseline: dict | None) -> tuple[str, dict | None]:
    """Return ('approved'|'denied'|'version_below_min'|'not_listed'|'no_baseline', entry)."""
    if not baseline:
        return "no_baseline", None
    names = " ".join(filter(None, [sw["product"], sw["description"], sw["file_name"]]))
    pubs = set(_norm(" ".join(filter(None, [sw["signer"], sw["vendor"]]))).split())

    def hit(entry: dict) -> bool:
        prod = _norm(entry.get("product"))
        if not prod or prod not in _norm(names):
            return False
        pub = set(_norm(entry.get("publisher")).split())
        return not pub or bool(pub & pubs)

    for e in baseline.get("denied", []) or []:
        if hit(e):
            return "denied", e
    for e in baseline.get("approved", []) or []:
        if hit(e):
            minv = parse_version(str(e["min_version"])) if e.get("min_version") else None
            have = parse_version(sw["product_version"] or sw["file_version"])
            if minv and have and _cmp(have, minv) < 0:
                return "version_below_min", e
            return "approved", e
    return "not_listed", None


# -------------------------------------------------------------------- analysis
def analyze(
    req: dict,
    *,
    policy: dict | None = None,
    controls: dict | None = None,
    baseline: dict | None = None,
    existing_rules: list[dict] | None = None,
    intel: Intel | None = None,
) -> Analysis:
    policy = policy or load_yaml(ROOT / "config" / "policy.yaml")
    controls = controls or load_yaml(ROOT / "config" / "cmmc_l2_rev2.yaml")
    cmap = controls.get("checks", {})
    sw = extract_software(req)
    checks: list[Check] = []

    def add(cid: str, result: str, title: str, detail: str, hard: bool = False, key: str | None = None) -> None:
        checks.append(Check(cid, result, title, detail, list(cmap.get(key or cid, [])), hard))

    state = _get(req, "computerState", "data", default={})
    user = _get(req, "event", "data", "user", default={})
    ctx = {
        "company": req.get("companyName"),
        "location": req.get("locationName"),
        "computer": req.get("computerName"),
        "os": _get(req, "event", "computerOperatingSystem"),
        "user": f"{user.get('domain')}\\{user.get('name')}" if user.get("name") else None,
        "request_type": req.get("requestType"),
        "requested_elevation": req.get("elevationType"),
        "approval_state": req.get("approvalState"),
        "duplicate_requests": req.get("duplicateRequestCount"),
        "ticket": _get(req, "ticketingSystemInfo", "ticketIdDisplay"),
        "explanation": req.get("elevationRequestExplanation") or None,
    }

    # Elevated sessions grant a whole admin session, not one program.
    if req.get("requestType") == "elevatedSession":
        add("privileged_binary", REVIEW, "Elevated session request",
            "Whole-session admin rights requested, not a single program. Least privilege needs a "
            "named task and the shortest duration; approve only with a documented reason.")
        add("change_record", INFO, "Change record",
            "Record the business reason and duration in the ticket (3.4.3 / 3.3.1).")
        return _finish(req, sw, ctx, checks, controls, policy, False, False)

    blob = " ".join(filter(None, [sw["file_name"], sw["product"], sw["description"], sw["vendor"], sw["signer"]]))
    fname = (sw["file_name"] or "").lower()

    # 1. Shells, LOLBins, OS components ------------------------------------
    priv_hit = fname in [b.lower() for b in policy.get("privileged_binaries", [])]
    is_os = _norm(sw["product"]) in [_norm(p) for p in policy.get("os_product_names", [])]
    wrapper = fname in [b.lower() for b in policy.get("wrapper_binaries", [])]
    if priv_hit:
        add("privileged_binary", FAIL, "Shell / living-off-the-land binary",
            f"{sw['file_name']} gives the user an elevated shell or system tool. No standing rule; "
            "a one-time approval needs a technician-confirmed task.", hard=False)
    elif is_os:
        add("privileged_binary", REVIEW, "Windows OS component",
            f"{sw['file_name']} is part of Windows. Don't create rules for OS components; "
            "one-time approval only if the task is confirmed.")
    elif wrapper:
        add("privileged_binary", REVIEW, "Wrapper binary",
            f"{sw['file_name']} launches something else. The real target is in the arguments: "
            f"{sw['arguments'] or '(none shown)'}. Vet that target, not the wrapper.")
    else:
        add("privileged_binary", PASS, "Not a shell, OS component or wrapper", sw["file_name"] or "")

    # 2. Signature ----------------------------------------------------------
    if not sw["signed"]:
        add("signature", FAIL, "Unsigned binary",
            "No Authenticode signature, so the publisher can't be verified. Escalate; approve only "
            "by hash with a documented source.")
    elif not sw["signature_verified"] or sw["cert_self_signed"] or sw["cert_error"]:
        add("signature", FAIL, "Signature not trusted",
            f"Signer '{sw['signer']}' failed verification"
            f"{' (self-signed)' if sw['cert_self_signed'] else ''}"
            f"{': ' + sw['cert_error'] if sw['cert_error'] else ''}.", hard=True)
    else:
        vend, signer = set(_norm(sw["vendor"]).split()), set(_norm(sw["signer"]).split())
        mismatch = vend and signer and not (vend & signer)
        exp = _parse_cert_date(sw["cert_valid_to"])
        notes = []
        if exp and exp < datetime.now():
            notes.append(f"signing cert expired {sw['cert_valid_to']} (timestamped signature still valid; "
                         "publisher rules will need a new thumbprint)")
        if mismatch:
            add("signature", REVIEW, "Signer doesn't match product vendor",
                f"Signed by '{sw['signer']}' but the file claims vendor '{sw['vendor']}'. Confirm the "
                "relationship before approving.")
        else:
            add("signature", PASS, "Valid publisher signature",
                f"Signed by {sw['signer']} via {sw['issuer']}" + (f"; {'; '.join(notes)}" if notes else ""))

    # 3. Prohibited / restricted categories --------------------------------
    cat_hit = None
    for name, cat in (policy.get("categories") or {}).items():
        term = _contains_any(blob, cat.get("match", []))
        if term and not _contains_any(blob, cat.get("allow", []) or []):
            cat_hit = (name, cat.get("action", "review"), term)
            break
    if cat_hit:
        name, action, term = cat_hit
        key = "remote_access" if name == "remote_access" else "functionality"
        res = FAIL if action == "deny" else REVIEW
        add(key, res, f"Restricted category: {name.replace('_', ' ')}",
            f"Matched '{term}'. Policy action: {action}.", hard=(action == "deny"))
    else:
        add("functionality", PASS, "No restricted category matched",
            "Not remote access, P2P, crypto, VPN/proxy, AI, consumer or dual-use admin tooling.")

    # 4. Approved software baseline (3.4.8) ---------------------------------
    status, entry = match_baseline(sw, baseline)
    prior = _prior_rules(sw, existing_rules or [], req.get("companyName"))
    prior_txt = f" Existing approved rules for this software in this client: {prior}." if prior else ""
    if status == "approved":
        add("baseline", PASS, "On the client's approved software baseline",
            f"Matches baseline entry '{entry.get('product')}'"
            f"{' (min ' + str(entry['min_version']) + ')' if entry.get('min_version') else ''}.{prior_txt}")
    elif status == "denied":
        add("baseline", FAIL, "On the client's denied software list",
            f"Matches denied entry '{entry.get('product')}': {entry.get('reason', 'no reason recorded')}.",
            hard=True)
    elif status == "version_below_min":
        add("baseline", FAIL, "Below the baseline's minimum version",
            f"Baseline requires {entry.get('product')} >= {entry.get('min_version')}; request is "
            f"{sw['product_version'] or sw['file_version']}.")
    elif status == "not_listed":
        add("baseline", REVIEW, "Not on the client's approved software baseline",
            "Permit-by-exception: approving adds this software to the client's authorized set. "
            "Get the client's sign-off and add it to the baseline file." + prior_txt)
    else:
        add("baseline", REVIEW, "No documented software baseline for this client",
            "3.4.8 can't be evidenced without an approved software list. Treat this approval as "
            "creating the first baseline entry." + prior_txt)

    # 5. User-installed software (3.4.9) ------------------------------------
    path = (sw["file_path"] or "").lower()
    up = _contains_any(path, policy.get("user_writable_paths", []))
    installer = bool(_contains_any(" ".join(filter(None, [fname, sw["description"]])),
                                   policy.get("installer_markers", [])))
    if path.startswith("\\\\"):
        add("user_installed", REVIEW, "Launched from a network share",
            f"{sw['file_path']}. Confirm the share is an approved software repository.")
    elif up:
        add("user_installed", INFO, "User-initiated install from a user-writable folder",
            f"{sw['file_path']}. This approval is the 3.4.9 control point; the analysis is the record.")
    else:
        add("user_installed", PASS, "Runs from a protected location", sw["file_path"] or "")

    # 6. Intel: VirusTotal, KEV, NVD, EOL -----------------------------------
    if intel:
        vt = intel.virustotal(sw["sha256"])
        if vt["status"] == "ok":
            if vt["malicious"] >= 2:
                add("malware_scan", FAIL, "VirusTotal detections",
                    f"{vt['malicious']} engines flag it as malicious"
                    f"{' (' + vt['popular_threat_label'] + ')' if vt.get('popular_threat_label') else ''}. "
                    f"{vt['link']}", hard=True)
            elif vt["malicious"] == 1 or vt["suspicious"] > 0:
                add("malware_scan", REVIEW, "Low-confidence VirusTotal detection",
                    f"{vt['malicious']} malicious / {vt['suspicious']} suspicious. Check for a false "
                    f"positive. {vt['link']}")
            else:
                add("malware_scan", PASS, "Clean on VirusTotal",
                    f"0 detections, {vt['harmless'] + vt['undetected']} engines. {vt['link']}")
        elif vt["status"] == "not_found":
            add("malware_scan", REVIEW, "Unknown to VirusTotal",
                "No prior scans of this exact file. Verify the download source matches the vendor's site.")
        else:
            add("malware_scan", REVIEW, "VirusTotal not checked", vt["detail"])

        version = sw["product_version"] or sw["file_version"]
        nvd = intel.cves_for_version(sw["product"], version)
        kev = intel.kev_for_product(sw["vendor"] or sw["signer"], sw["product"])
        affecting_ids = {c["id"] for c in nvd.get("affecting_version", [])} if nvd["status"] == "ok" else set()
        if kev["status"] == "ok":
            kev_ids = {h["cveID"] for h in kev["hits"]}
            on_version = kev_ids & affecting_ids
            if on_version:
                add("known_exploited", FAIL, "Known exploited vulnerability in this version",
                    f"CISA KEV: {', '.join(sorted(on_version))}. Approve only a patched version.", hard=True)
            elif kev_ids and nvd["status"] == "ok" and kev_ids <= set(nvd.get("product_cve_ids", [])) \
                    and parse_version(version):
                add("known_exploited", PASS, "KEV entries are fixed before this version",
                    f"{', '.join(sorted(kev_ids)[:6])} are in CISA KEV, but NVD's affected ranges "
                    f"exclude {version}.")
            elif kev_ids:
                add("known_exploited", REVIEW, "Product has KEV entries",
                    f"{', '.join(sorted(kev_ids)[:6])} affect this product; NVD didn't tie them to "
                    f"version {version}. Confirm this version is patched.")
            else:
                add("known_exploited", PASS, "No CISA KEV entries for this product",
                    f"Checked {sw['vendor'] or sw['signer']} {sw['product']} against the KEV catalog.")
        else:
            add("known_exploited", REVIEW, "KEV not checked", kev["detail"])

        if nvd["status"] == "ok":
            aff = nvd["affecting_version"]
            high = [c for c in aff if (c["cvss"] or 0) >= 7]
            if high:
                top = ", ".join(f"{c['id']} ({c['cvss']})" for c in high[:5])
                add("cve_exposure", REVIEW, "High/critical CVEs affect this version",
                    f"{len(high)} with CVSS >= 7: {top}. Prefer the patched release.")
            elif aff:
                add("cve_exposure", INFO, "Lower-severity CVEs affect this version",
                    ", ".join(c["id"] for c in aff[:5]))
            else:
                add("cve_exposure", PASS, "No NVD CVEs matched to this version",
                    f"{nvd['product_cve_total']} CVEs on record for the product; none cover {version}.")
        else:
            add("cve_exposure", REVIEW, "NVD not checked", nvd["detail"])

        slug = None
        for kw, s in (policy.get("endoflife_products") or {}).items():
            if _contains_any(blob, [kw]):
                slug = s
                break
        if slug:
            e = intel.end_of_life(slug, version)
            if e["status"] == "ok" and e["is_eol"]:
                add("end_of_life", FAIL, "End-of-life version",
                    f"{slug} {e['cycle']} reached end of life {e['eol']}; latest is {e['latest']}.")
            elif e["status"] == "ok":
                add("end_of_life", PASS, "Supported release",
                    f"{slug} {e['cycle']} supported until {e['eol']}.")
            else:
                add("end_of_life", INFO, "Lifecycle not determined", e["detail"])
    else:
        add("malware_scan", REVIEW, "Threat intel not run", "Run with intel enabled before approving.")

    # 7. Device posture -----------------------------------------------------
    issues = []
    if state.get("isAntivirusEnabled") is False:
        issues.append("antivirus disabled")
    if state.get("isAntivirusUpToDate") is False:
        issues.append("antivirus out of date")
    if state.get("isWindowsUpdateEnabled") is False:
        issues.append("Windows Update disabled")
    if state.get("technicianMode"):
        issues.append("technician mode active")
    if issues:
        add("device_posture", REVIEW, "Device posture issues", "; ".join(issues) + ".")
    else:
        add("device_posture", PASS, "Device posture OK",
            "AV enabled and current, Windows Update on (per AutoElevate agent). Check Ninja/EDR for full status.")

    return _finish(req, sw, ctx, checks, controls, policy, installer, priv_hit or is_os)


def _prior_rules(sw: dict, rules: list[dict], company: str | None) -> str:
    md5 = (sw.get("md5") or "").lower()
    same_hash = [r for r in rules if r.get("approved") and not r.get("deleted") and
                 (str(r.get("triggerIdentifier", "")).lower() == md5 or
                  str(_get(r, "identificationCriteria", "file", "fileHash", "md5", default="")).lower() == md5)]
    prod = _norm(sw.get("product"))
    same_prod = [r for r in rules if r.get("approved") and not r.get("deleted") and prod and
                 prod in _norm(_get(r, "fileInfo", "productName", default="")) and
                 (not company or r.get("companyName") == company)]
    parts = []
    if same_hash:
        parts.append(f"{len(same_hash)} for this exact hash")
    if same_prod:
        parts.append(f"{len(same_prod)} for this product")
    return ", ".join(parts)


def _finish(req, sw, ctx, checks, controls, policy, installer, no_standing_rule) -> Analysis:
    cmap = controls.get("checks", {})
    checks.append(Check("change_record", INFO, "Change record",
                        "This analysis, the decision and the AutoElevate audit log form the change record. "
                        "Post the CW note on the request's ticket.",
                        list(cmap.get("change_record", []))))

    hard = [c for c in checks if c.result == FAIL and c.hard]
    soft = [c for c in checks if c.result in (FAIL, REVIEW)]
    if hard:
        verdict = "DENY"
        rec = Recommendation("deny", rationale="; ".join(c.title for c in hard))
    elif soft:
        verdict = "ESCALATE"
        rec = Recommendation("escalate", rationale="; ".join(c.title for c in soft))
    else:
        verdict = "APPROVE"
        if installer or no_standing_rule:
            rec = Recommendation("approve", create_rule=False, elevation_type=req.get("elevationType"),
                                 rationale="One-time approval: installer or non-ruleable binary, no standing rule.")
        else:
            rec = Recommendation("approve", create_rule=True, rule_level="computer",
                                 elevation_type=req.get("elevationType"),
                                 rationale="Recurring app: computer-level rule (narrowest scope). "
                                           "Widen only when the baseline names more users.")
    if verdict != "APPROVE" and installer:
        rec.rationale += ". If approved after review: one-time, no rule."
    if verdict != "APPROVE" and no_standing_rule:
        rec.rationale += ". Never create a standing rule for this binary."

    return Analysis(
        request_id=req.get("id"),
        verdict=verdict,
        framework=controls.get("framework", ""),
        software=sw,
        context=ctx,
        checks=checks,
        recommendation=rec,
        analyzed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


# ------------------------------------------------------------------ rendering
ICON = {PASS: "PASS", REVIEW: "REVIEW", FAIL: "FAIL", INFO: "INFO"}


def render_markdown(a: Analysis) -> str:
    s, c, r = a.software, a.context, a.recommendation
    lines = [
        f"## {a.verdict}: {s.get('product') or s.get('file_name')} {s.get('product_version') or ''}".rstrip(),
        f"{c['company']} / {c['location']} / {c['computer']} · user {c['user']} · "
        f"CW ticket {c['ticket']} · request {a.request_id}",
        "",
        f"**File:** {s.get('file_name')} ({s.get('description')}) · signer {s.get('signer') or 'none'} · "
        f"SHA-256 `{s.get('sha256')}`",
        "",
        "| Check | Result | Practices | Detail |",
        "|---|---|---|---|",
    ]
    for ch in a.checks:
        lines.append(f"| {ch.title} | {ICON[ch.result]} | {', '.join(ch.practices)} | {ch.detail} |")
    lines += ["", f"**Recommendation:** {r.decision.upper()}"
              + (f" · rule: {r.rule_level}" if r.create_rule else " · no standing rule" if r.decision == "approve" else "")
              + (f" · elevation: {r.elevation_type}" if r.elevation_type else ""),
              r.rationale, "", f"_{a.framework} · analyzed {a.analyzed_at}_"]
    return "\n".join(lines)


def render_cw_note(a: Analysis, decision: str | None = None, decided_by: str | None = None,
                   override_reason: str | None = None) -> str:
    s, c, r = a.software, a.context, a.recommendation
    out = [
        f"AutoElevate pre-approval analysis ({a.framework})",
        f"Request {a.request_id} | {c['computer']} | user {c['user']}",
        f"Software: {s.get('product')} {s.get('product_version') or ''} | {s.get('file_name')} | "
        f"signer {s.get('signer') or 'unsigned'}",
        f"SHA-256: {s.get('sha256')}",
        f"Verdict: {a.verdict} | Recommended: {r.decision}"
        + (f", {r.rule_level} rule" if r.create_rule else ""),
        "",
    ]
    for ch in a.checks:
        if ch.id == "change_record":
            continue
        out.append(f"[{ch.result}] {ch.title} ({', '.join(ch.practices)}): {ch.detail}")
    out.append("")
    if decision:
        out.append(f"Decision: {decision.upper()}" + (f" by {decided_by}" if decided_by else ""))
        if override_reason:
            out.append(f"Override of {a.verdict} verdict. Justification: {override_reason}")
    else:
        out.append("Decision: pending")
    out.append(f"Analyzed {a.analyzed_at}. Evidence for CM.L2-3.4.3, CM.L2-3.4.4, AU.L2-3.3.1.")
    return "\n".join(out)
