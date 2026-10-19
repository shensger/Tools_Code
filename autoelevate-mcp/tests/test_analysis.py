import copy
import json
from pathlib import Path

import pytest

from autoelevate_mcp.analysis import ROOT, analyze, load_yaml, match_baseline, extract_software, render_cw_note

FIX = Path(__file__).parent / "fixtures"


class FakeIntel:
    def __init__(self, vt=None, kev=None, nvd=None, eol=None):
        self._vt = vt or {"status": "ok", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 70,
                          "link": "https://vt/x"}
        self._kev = kev or {"status": "ok", "hits": []}
        self._nvd = nvd or {"status": "ok", "product_cve_total": 0, "product_cve_ids": [], "affecting_version": []}
        self._eol = eol or {"status": "unknown", "detail": "n/a"}

    def virustotal(self, sha):
        return self._vt

    def kev_for_product(self, vendor, product):
        return self._kev

    def cves_for_version(self, product, version):
        return self._nvd

    def end_of_life(self, slug, version):
        return self._eol


@pytest.fixture
def req():
    return json.loads((FIX / "request_installer.json").read_text())


@pytest.fixture
def baseline():
    return load_yaml(ROOT / "baselines" / "_example.yaml")


def trig(r):
    return r["event"]["data"]["trigger"]


def check(a, cid):
    return next(c for c in a.checks if c.id == cid)


def test_clean_installer_on_baseline_is_one_time_approve(req, baseline):
    a = analyze(req, baseline=baseline, intel=FakeIntel())
    assert a.verdict == "APPROVE"
    assert a.recommendation.create_rule is False
    assert a.recommendation.rule_level is None


def test_recurring_app_gets_computer_level_rule(req, baseline):
    t = trig(req)
    t.update(fileName="mcuxpressoide.exe", fileDescription="MCUXpresso IDE", uacTitle="MCUXpresso IDE",
             filePath="C:\\NXP\\MCUXpressoIDE\\ide\\mcuxpressoide.exe")
    a = analyze(req, baseline=baseline, intel=FakeIntel())
    assert a.verdict == "APPROVE"
    assert a.recommendation.create_rule and a.recommendation.rule_level == "computer"


def test_no_baseline_escalates(req):
    a = analyze(req, baseline=None, intel=FakeIntel())
    assert a.verdict == "ESCALATE"
    assert check(a, "baseline").practices == ["CM.L2-3.4.8"]


def test_vt_detections_deny(req, baseline):
    vt = {"status": "ok", "malicious": 12, "suspicious": 0, "harmless": 0, "undetected": 50,
          "popular_threat_label": "trojan.x", "link": "l"}
    a = analyze(req, baseline=baseline, intel=FakeIntel(vt=vt))
    assert a.verdict == "DENY"


def test_kev_on_this_version_denies(req, baseline):
    kev = {"status": "ok", "hits": [{"cveID": "CVE-2025-0001"}]}
    nvd = {"status": "ok", "product_cve_total": 1, "product_cve_ids": ["CVE-2025-0001"],
           "affecting_version": [{"id": "CVE-2025-0001", "cvss": 9.8, "summary": "x"}]}
    a = analyze(req, baseline=baseline, intel=FakeIntel(kev=kev, nvd=nvd))
    assert a.verdict == "DENY"
    assert check(a, "known_exploited").result == "FAIL"


def test_kev_fixed_before_version_passes(req, baseline):
    kev = {"status": "ok", "hits": [{"cveID": "CVE-2025-0001"}]}
    nvd = {"status": "ok", "product_cve_total": 1, "product_cve_ids": ["CVE-2025-0001"], "affecting_version": []}
    a = analyze(req, baseline=baseline, intel=FakeIntel(kev=kev, nvd=nvd))
    assert check(a, "known_exploited").result == "PASS"
    assert a.verdict == "APPROVE"


def test_powershell_never_gets_rule(req, baseline):
    t = trig(req)
    t.update(fileName="powershell.exe", productName="Microsoft Windows Operating System",
             fileDescription="Windows PowerShell", productCompany="Microsoft Corporation",
             filePath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    t["publisherCertInfo"]["subject"] = "CN=Microsoft Windows, O=Microsoft Corporation"
    a = analyze(req, baseline=baseline, intel=FakeIntel())
    assert a.verdict == "ESCALATE"
    assert check(a, "privileged_binary").result == "FAIL"
    assert "Never create a standing rule" in a.recommendation.rationale


def test_remote_access_tool_denied(req, baseline):
    t = trig(req)
    t.update(fileName="AnyDesk.exe", productName="AnyDesk", fileDescription="AnyDesk",
             productCompany="AnyDesk Software GmbH")
    t["publisherCertInfo"]["subject"] = "CN=AnyDesk Software GmbH"
    a = analyze(req, baseline=None, intel=FakeIntel())
    assert a.verdict == "DENY"
    assert "AC.L2-3.1.12" in check(a, "remote_access").practices


def test_baseline_denied_list(req, baseline):
    t = trig(req)
    t.update(productName="AnyDesk", fileName="anydesk.exe", fileDescription="AnyDesk")
    status, _ = match_baseline(extract_software(req), baseline)
    assert status == "denied"


def test_baseline_min_version(req, baseline):
    trig(req).update(productVersion="24.1", fileVersion="24.1")
    status, _ = match_baseline(extract_software(req), baseline)
    assert status == "version_below_min"


def test_untrusted_signature_denies(req, baseline):
    c = trig(req)["publisherCertInfo"]
    c.update(isSelfSigned=True)
    a = analyze(req, baseline=baseline, intel=FakeIntel())
    assert a.verdict == "DENY"


def test_unsigned_escalates(req, baseline):
    trig(req).update(isSigned=False, isPublisherCertVerified=False)
    a = analyze(req, baseline=baseline, intel=FakeIntel())
    assert a.verdict == "ESCALATE"


def test_av_off_escalates(req, baseline):
    req["computerState"]["data"]["isAntivirusEnabled"] = False
    a = analyze(req, baseline=baseline, intel=FakeIntel())
    assert a.verdict == "ESCALATE"


def test_elevated_session_always_escalates(req):
    req["requestType"] = "elevatedSession"
    a = analyze(req, intel=FakeIntel())
    assert a.verdict == "ESCALATE"


def test_eol_escalates(req, baseline):
    trig(req).update(productName="Python 3.8.10 (64-bit)", fileName="python-3.8.10-amd64.exe",
                     fileDescription="Python 3.8.10 (64-bit)", productVersion="3.8.10")
    eol = {"status": "ok", "cycle": "3.8", "eol": "2024-10-07", "is_eol": True, "latest": "3.8.20"}
    a = analyze(req, baseline=None, intel=FakeIntel(eol=eol))
    assert check(a, "end_of_life").result == "FAIL"


def test_cw_note_records_override(req, baseline):
    a = analyze(req, baseline=None, intel=FakeIntel())
    note = render_cw_note(a, decision="approve", decided_by="Shawn", override_reason="Client approved via email")
    assert "Override of ESCALATE verdict" in note and "CM.L2-3.4.4" in note


def test_sanctioned_remote_tool_allowed(req, baseline):
    t = trig(req)
    t.update(fileName="SplashtopSOS.exe", productName="Splashtop SOS", fileDescription="Splashtop SOS",
             productCompany="Splashtop Inc.")
    t["publisherCertInfo"]["subject"] = "CN=Splashtop Inc."
    policy = load_yaml(ROOT / "config" / "policy.yaml")
    assert analyze(copy.deepcopy(req), policy=policy, intel=FakeIntel()).verdict == "DENY"
    policy["categories"]["remote_access"]["allow"] = ["splashtop sos"]
    a = analyze(req, policy=policy, intel=FakeIntel())
    assert a.verdict != "DENY"


class NoVTIntel(FakeIntel):
    def virustotal(self, sha):
        return {"status": "skipped", "detail": "VT_API_KEY not set."}


def test_vt_optional_when_policy_allows(req, baseline):
    policy = load_yaml(ROOT / "config" / "policy.yaml")
    policy["require_virustotal"] = False
    a = analyze(copy.deepcopy(req), policy=policy, baseline=baseline, intel=NoVTIntel())
    assert check(a, "malware_scan").result == "INFO" and a.verdict == "APPROVE"
    policy["require_virustotal"] = True
    a = analyze(req, policy=policy, baseline=baseline, intel=NoVTIntel())
    assert a.verdict == "ESCALATE"
