"""Server tools against a mocked AutoElevate API (no network)."""

import base64
import json
import time
from pathlib import Path

import httpx
import pytest
import respx

from autoelevate_mcp import server
from autoelevate_mcp.client import API_BASE, AutoElevateClient

from test_analysis import FakeIntel

FIX = Path(__file__).parent / "fixtures"
RID = "00000000-0000-0000-0000-000000000001"


def _jwt(exp):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256'})}.{enc({'id': 'u', 'exp': exp})}.sig"


@pytest.fixture
def api(monkeypatch, tmp_path):
    req = json.loads((FIX / "request_installer.json").read_text())
    with respx.mock(base_url=API_BASE, assert_all_called=False) as mock:
        mock.get(f"/requests/{RID}").respond(json={"request": req})
        mock.get("/requests/getIdByTicketId").respond(json={"id": RID})
        mock.get("/companies").respond(json={"items": [{"id": "c1", "name": "Example Client"}], "totalCount": 1})
        mock.get("/rules").respond(json={"items": [{
            "id": "r1", "approved": True, "deleted": False, "companyName": "Example Client",
            "locationName": "Main Office", "computerName": "PC-TEST01", "createdByName": "Tech",
            "createdAt": "1792432377854", "shouldIgnore": False,
            "fileInfo": {"fileName": "powershell.exe", "productName": "Microsoft Windows Operating System"}}],
            "totalCount": 1})
        decide = mock.post(f"/requests/{RID}/approve").respond(
            json={"id": RID, "approvalState": "APPROVED", "ruleCreated": False})
        server._client = AutoElevateClient(token=_jwt(time.time() + 3600))
        server._intel = FakeIntel()
        server._analyses.clear()
        monkeypatch.setenv("AE_BASELINE_DIR", str(tmp_path))
        yield mock, decide


def test_analyze_by_ticket(api):
    out = server.ae_analyze_request(ticket_id=100001)
    assert out["verdict"] == "ESCALATE"  # no baseline in tmp dir
    assert out["cw_ticket"] == 100001
    assert "CM.L2-3.4.8" in out["markdown"]


def test_decide_requires_confirm_and_analysis(api):
    assert "confirm" in server.ae_decide_request(RID, "approve")["error"]
    assert "ae_analyze_request" in server.ae_decide_request(RID, "approve", confirm=True)["error"]


def test_decide_escalate_needs_override(api):
    _, decide = api
    server.ae_analyze_request(request_id=RID)
    assert "override_reason" in server.ae_decide_request(RID, "approve", confirm=True)["error"]
    assert not decide.called
    out = server.ae_decide_request(RID, "approve", confirm=True, override_reason="Client sign-off by email",
                                   decided_by="Shawn")
    assert decide.called
    body = json.loads(decide.calls.last.request.content)
    assert body["createRule"] is False and body["ruleLevel"] is None and body["elevationType"] == "admin"
    assert decide.calls.last.request.headers["Accept"] == "application/json"
    assert "Override of ESCALATE verdict" in out["cw_note"]


def test_decide_blocks_msp_level_rule(api):
    server.ae_analyze_request(request_id=RID)
    out = server.ae_decide_request(RID, "approve", confirm=True, override_reason="x", create_rule=True,
                                   rule_level="msp")
    assert "rule_level" in out["error"]


def test_audit_flags_powershell_rule(api):
    out = server.ae_audit_rules()
    assert out["findings"][0]["severity"] == "HIGH"
    assert out["findings"][0]["practice"] == "AC.L2-3.1.7"


def test_login_flow_with_totp():
    with respx.mock(base_url=API_BASE) as mock:
        mock.post("/users/login").respond(json={"token": "mfa-token"})
        verify = mock.post("/users/adminPortalOtpVerify").respond(
            json={"user": {}}, headers={"authorization": _jwt(time.time() + 86400)})
        mock.get("/companies").respond(json={"items": [], "totalCount": 0})
        c = AutoElevateClient(email="svc@x", password="p", totp_secret="JBSWY3DPEHPK3PXP")
        c.list_companies()
        body = json.loads(verify.calls.last.request.content)
        assert body["mfaToken"] == "mfa-token" and len(body["code"]) == 6


def test_analyze_writes_report(api, tmp_path, monkeypatch):
    monkeypatch.setenv("AE_REPORT_DIR", str(tmp_path / "reports"))
    out = server.ae_analyze_request(request_id=RID)
    p = Path(out["report_path"])
    assert p.exists() and p.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "Executive Summary: MCUXpresso IDE 25.6" in out["report_html"]
    assert "NEEDS AUTHORIZATION" in out["report_html"]
