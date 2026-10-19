"""AutoElevate MCP server with CMMC Level 2 pre-approval analysis.

Run:  autoelevate-mcp            (stdio, for Claude Desktop)
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .analysis import ROOT, Analysis, analyze, load_yaml, render_cw_note, render_markdown, _get, _norm, _contains_any
from .client import ELEVATION_TYPES, RULE_LEVELS, AutoElevateClient
from .intel import Intel
from .report import render_html

INSTRUCTIONS = """AutoElevate (CyberFOX) privilege management for an MSP.

Approval workflow - always in this order:
1. ae_analyze_request on the request (by AutoElevate request id or ConnectWise ticket number).
2. Show the user the executive summary: publish `report_html` as an artifact when you can,
   otherwise give them `report_path`. Don't approve on your own judgment.
3. Post the returned cw_note to the request's ConnectWise ticket with the ConnectWise tools.
4. Only after the user explicitly says to, call ae_decide_request with confirm=true.
   An APPROVE against a DENY or ESCALATE verdict needs the user's override_reason.
"""

mcp = MCPServer("autoelevate", instructions=INSTRUCTIONS)

_client: AutoElevateClient | None = None
_intel: Intel | None = None
_analyses: dict[str, tuple[float, Analysis]] = {}
ANALYSIS_TTL = 2 * 3600

READ = ToolAnnotations(read_only_hint=True, open_world_hint=True)


def client() -> AutoElevateClient:
    global _client
    if _client is None:
        _client = AutoElevateClient()
    return _client


def intel() -> Intel:
    global _intel
    if _intel is None:
        _intel = Intel()
    return _intel


def _config() -> tuple[dict, dict]:
    policy = load_yaml(Path(os.environ.get("AE_POLICY", ROOT / "config" / "policy.yaml")))
    controls = load_yaml(Path(os.environ.get("AE_CONTROL_MAP", ROOT / "config" / "cmmc_l2_rev2.yaml")))
    return policy, controls


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")


def load_baseline(company: str | None) -> dict | None:
    """Find baselines/<company-slug>.yaml, or any baseline whose `company:` matches."""
    if not company:
        return None
    d = Path(os.environ.get("AE_BASELINE_DIR", ROOT / "baselines"))
    if not d.is_dir():
        return None
    direct = d / f"{_slug(company)}.yaml"
    if direct.exists():
        return load_yaml(direct)
    for f in d.glob("*.yaml"):
        data = load_yaml(f)
        names = [data.get("company")] + list(data.get("aliases") or [])
        if any(_slug(n) == _slug(company) for n in names if n):
            return data
    return None


def _company_id(name: str | None) -> str | None:
    if not name:
        return None
    for c in client().list_companies():
        if _slug(c.get("name")) == _slug(name) or c.get("id") == name:
            return c["id"]
    raise ValueError(f"No AutoElevate company named '{name}'. Use ae_list_companies.")


def _resolve(request_id: str | None, ticket_id: int | None) -> str:
    if request_id:
        return request_id
    if ticket_id:
        return client().request_id_for_ticket(ticket_id)
    raise ValueError("Give request_id or ticket_id.")


def _summary(r: dict) -> dict:
    t = _get(r, "event", "data", "trigger", default={})
    u = _get(r, "event", "data", "user", default={})
    return {
        "request_id": r.get("id"),
        "state": r.get("approvalState"),
        "type": r.get("requestType"),
        "company": r.get("companyName"),
        "location": r.get("locationName"),
        "computer": r.get("computerName"),
        "user": f"{u.get('domain')}\\{u.get('name')}" if u.get("name") else None,
        "software": t.get("productName") or t.get("fileDescription"),
        "version": t.get("productVersion") or t.get("fileVersion"),
        "file": t.get("fileName"),
        "signer": _get(t, "publisherCertInfo", "subject", default="").split(",")[0].replace("CN=", "") or None,
        "ticket": _get(r, "ticketingSystemInfo", "ticketIdDisplay"),
        "created": time.strftime("%Y-%m-%d %H:%M", time.localtime(int(r.get("createdAt", 0)) / 1000)),
    }


# ----------------------------------------------------------------------- tools
@mcp.tool(annotations=READ)
def ae_list_companies() -> list[dict]:
    """List AutoElevate companies (clients) with their ids."""
    return [{"id": c["id"], "name": c["name"], "psa_company_id": c.get("managementSystemCompanyId")}
            for c in client().list_companies() if not c.get("deleted")]


@mcp.tool(annotations=READ)
def ae_list_requests(company: str | None = None, days: int = 7, pending_only: bool = True) -> list[dict]:
    """List elevation requests from the last `days` days, newest first.

    company: AutoElevate company name or id (optional). pending_only: only PENDING requests.
    """
    reqs = client().list_requests(days=days, company_id=_company_id(company))
    if pending_only:
        reqs = [r for r in reqs if r.get("approvalState") == "PENDING"]
    return [_summary(r) for r in reqs]


@mcp.tool(annotations=READ)
def ae_get_request(request_id: str | None = None, ticket_id: int | None = None) -> dict:
    """Get one elevation request (by AutoElevate id or ConnectWise ticket number) with file,
    signature and device details. Large binary fields are dropped."""
    r = client().get_request(_resolve(request_id, ticket_id))
    trig = _get(r, "event", "data", "trigger", default={})
    trig.pop("icon", None)
    (trig.get("publisherCertInfo") or {}).pop("publicKey", None)
    _get(r, "event", "data", default={}).pop("allElementValues", None)
    return r


@mcp.tool(annotations=READ)
def ae_analyze_request(request_id: str | None = None, ticket_id: int | None = None,
                       run_intel: bool = True) -> dict:
    """CMMC Level 2 (NIST 800-171 Rev 2) pre-approval analysis of an elevation request.

    Checks signature, VirusTotal, CISA KEV, NVD CVEs for the exact version, end-of-life,
    the client's approved software baseline (3.4.8), restricted categories (remote access,
    P2P, AI, consumer, dual-use), shells/OS binaries, device posture, and recommends the
    narrowest approval scope. Returns a verdict (APPROVE / ESCALATE / DENY), a markdown
    table, `cw_note` text to post on the ConnectWise ticket, and a one-slide executive
    summary: `report_path` (HTML saved under ~/AutoElevateReports) and `report_html`
    (the same page as an artifact-ready fragment; publish it to show the user).
    """
    rid = _resolve(request_id, ticket_id)
    req = client().get_request(rid)
    policy, controls = _config()
    company = req.get("companyName")
    try:
        rules = client().list_rules(company_id=_company_id(company))
    except Exception:  # noqa: BLE001
        rules = []
    a = analyze(req, policy=policy, controls=controls, baseline=load_baseline(company),
                existing_rules=rules, intel=intel() if run_intel else None)
    _analyses[rid] = (time.time(), a)
    report_path = None
    try:
        out_dir = Path(os.environ.get("AE_REPORT_DIR", Path.home() / "AutoElevateReports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = "_".join(filter(None, [time.strftime("%Y%m%d"), str(a.context.get("ticket") or rid[:8]),
                                      _slug(a.software.get("product") or a.software.get("file_name") or "")]))
        report_path = out_dir / f"{stem}.html"
        report_path.write_text(render_html(a), encoding="utf-8")
    except Exception:  # noqa: BLE001
        report_path = None
    return {
        "report_path": str(report_path) if report_path else None,
        "report_html": render_html(a, standalone=False),
        "verdict": a.verdict,
        "recommendation": a.recommendation.__dict__,
        "markdown": render_markdown(a),
        "cw_note": render_cw_note(a),
        "cw_ticket": a.context.get("ticket"),
        "approval_state": a.context.get("approval_state"),
        "checks": [c.__dict__ for c in a.checks],
    }


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False,
                                      open_world_hint=True))
def ae_decide_request(
    request_id: str,
    decision: str,
    confirm: bool = False,
    create_rule: bool = False,
    rule_level: str | None = None,
    elevation_type: str | None = None,
    denial_reason: str | None = None,
    override_reason: str | None = None,
    decided_by: str | None = None,
) -> dict:
    """Approve or deny an elevation request. ONLY call after the user explicitly approves the action.

    Requires a fresh ae_analyze_request for the same request in this session.
    decision: "approve" or "deny". confirm must be true.
    create_rule + rule_level ("computer" | "location" | "company") make a standing rule; omit for one-time.
    elevation_type: "admin" | "user" (defaults to what the request asked for).
    override_reason: required to approve when the verdict was DENY or ESCALATE (the user's words).
    Returns the AutoElevate result and an updated cw_note recording the decision.
    """
    if not confirm:
        return {"error": "Not executed: confirm=true is required, after the user approves this action."}
    if decision not in ("approve", "deny"):
        return {"error": "decision must be 'approve' or 'deny'."}
    cached = _analyses.get(request_id)
    if not cached or time.time() - cached[0] > ANALYSIS_TTL:
        return {"error": "Run ae_analyze_request on this request first (analysis missing or older than 2h)."}
    a = cached[1]
    if a.context.get("approval_state") not in (None, "PENDING"):
        return {"error": f"Request is already {a.context['approval_state']}."}
    if decision == "approve":
        if a.verdict != "APPROVE" and not override_reason:
            return {"error": f"Verdict was {a.verdict}. Approving needs override_reason from the user."}
        if create_rule:
            if rule_level not in RULE_LEVELS:
                return {"error": f"rule_level must be one of {RULE_LEVELS}. All-companies rules aren't allowed here."}
            if any(c.id == "privileged_binary" and c.result != "PASS" for c in a.checks):
                return {"error": "No standing rules for shells, OS components or wrapper binaries. "
                                 "Approve one-time (create_rule=false)."}
        if elevation_type and elevation_type not in ELEVATION_TYPES:
            return {"error": f"elevation_type must be one of {ELEVATION_TYPES}."}
    result = client().decide_request(
        request_id, decision,
        create_rule=create_rule if decision == "approve" else False,
        rule_level=rule_level if (decision == "approve" and create_rule) else None,
        elevation_type=(elevation_type or a.context.get("requested_elevation")) if decision == "approve" else None,
        denial_reason=denial_reason or (a.recommendation.rationale if decision == "deny" else None),
    )
    _analyses.pop(request_id, None)
    return {
        "result": {k: result.get(k) for k in ("id", "approvalState", "ruleCreated", "ruleLevel", "elevationType")}
        if isinstance(result, dict) else result,
        "cw_note": render_cw_note(a, decision=decision, decided_by=decided_by,
                                  override_reason=override_reason if decision == "approve" else None),
        "cw_ticket": a.context.get("ticket"),
    }


@mcp.tool(annotations=READ)
def ae_audit_rules(company: str | None = None) -> dict:
    """Audit existing elevation rules against CMMC L2 least privilege / least functionality.

    Flags rules for shells and OS binaries, all-companies (MSP-level) rules, ignore rules,
    restricted categories, and software missing from the client's baseline.
    """
    policy, controls = _config()
    priv = [b.lower() for b in policy.get("privileged_binaries", [])]
    os_names = [_norm(p) for p in policy.get("os_product_names", [])]
    rules = [r for r in client().list_rules(company_id=_company_id(company)) if not r.get("deleted")]
    findings = []
    for r in rules:
        fi = r.get("fileInfo") or {}
        fname = (fi.get("fileName") or "").lower()
        blob = " ".join(filter(None, [fi.get("fileName"), fi.get("productName"), fi.get("fileDescription"),
                                      fi.get("vendor")]))
        level = ("computer" if r.get("computerName") else "location" if r.get("locationName")
                 else "company" if r.get("companyName") else "msp")
        issues = []
        if r.get("approved") and fname in priv:
            issues.append(("HIGH", "Standing rule for a shell / LOLBin", "AC.L2-3.1.7"))
        elif r.get("approved") and _norm(fi.get("productName")) in os_names:
            issues.append(("MEDIUM", "Rule for a Windows OS component", "AC.L2-3.1.5"))
        if level == "msp" and r.get("approved"):
            issues.append(("HIGH", "All-companies rule", "AC.L2-3.1.5"))
        if r.get("shouldIgnore"):
            issues.append(("LOW", "Ignore rule (UAC shown, not managed)", "CM.L2-3.4.8"))
        for name, cat in (policy.get("categories") or {}).items():
            term = _contains_any(blob, cat.get("match", []))
            if term and r.get("approved") and not _contains_any(blob, cat.get("allow", []) or []):
                sev = "HIGH" if cat.get("action") == "deny" else "MEDIUM"
                issues.append((sev, f"Approved {name.replace('_', ' ')} ({term})",
                               "AC.L2-3.1.12" if name == "remote_access" else "CM.L2-3.4.7"))
                break
        for sev, why, practice in issues:
            findings.append({
                "severity": sev, "issue": why, "practice": practice, "rule_id": r.get("id"),
                "level": level, "company": r.get("companyName"), "location": r.get("locationName"),
                "computer": r.get("computerName"), "file": fi.get("fileName"), "product": fi.get("productName"),
                "created_by": r.get("createdByName"),
                "created": time.strftime("%Y-%m-%d", time.localtime(int(r.get("createdAt", 0)) / 1000)),
            })
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["company"] or "", f["file"] or ""))
    return {"rules_checked": len(rules), "findings": findings}


@mcp.tool(annotations=READ)
def ae_list_computers(company: str | None = None) -> list[dict]:
    """List computers with the AutoElevate agent: version, elevation mode, AV/Windows Update state."""
    out = []
    for item in client().list_computers(company_id=_company_id(company)):
        c = item.get("computer", item)
        if c.get("deleted"):
            continue
        st = _get(item, "currentState", "data", default={})
        out.append({
            "id": c.get("id"), "name": _get(c, "data", "machineName"),
            "serial": _get(c, "data", "serialNumber"), "os": _get(c, "data", "operatingSystem"),
            "company": c.get("companyName"), "location": c.get("locationName"),
            "last_check_in": time.strftime("%Y-%m-%d %H:%M", time.localtime(int(c.get("checkedInAt") or 0) / 1000)),
            "agent_version": st.get("agentVersion"), "elevation_mode": st.get("elevationMode"),
            "av_enabled": st.get("isAntivirusEnabled"), "av_current": st.get("isAntivirusUpToDate"),
            "windows_update": st.get("isWindowsUpdateEnabled"), "technician_mode": st.get("technicianMode"),
            "local_admins": _get(st, "adminMembers", "count"),
        })
    return out


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
