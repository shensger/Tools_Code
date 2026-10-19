import json
from pathlib import Path

from autoelevate_mcp import server
from autoelevate_mcp.vendor import COND, FAIL, FAIL_CUI, PASS, evaluate, render_vendor_html

FIX = json.loads((Path(__file__).parent / "fixtures" / "vendor_confluence.json").read_text(encoding="utf-8"))


def results(r):
    return {c.id: c.result for c in r.controls}


def test_confluence_cloud_matches_review():
    r = evaluate(FIX["intake"], FIX["facts"])
    assert r.decision == "CONDITIONAL"
    assert r.counts() == {PASS: 4, COND: 5, FAIL_CUI: 3, FAIL: 0}
    res = results(r)
    assert res["SA-9"] == FAIL_CUI and res["3.13.11"] == FAIL_CUI and res["3.11.1"] == FAIL_CUI
    assert res["SR-6"] == PASS and res["CM-10"] == PASS and res["3.4.9"] == COND
    assert "Free fails" in " ".join(r.conditions)
    assert any("Marketplace" in x for x in r.at_risk)


def test_cui_confirmed_denies():
    r = evaluate(FIX["intake"], {**FIX["facts"], "cui": "yes"})
    assert r.decision == "DENY"
    assert results(r)["SA-9"] == FAIL


def test_fedramp_moderate_passes_cui_controls():
    r = evaluate(FIX["intake"], {**FIX["facts"], "cui": "yes", "fedramp": "moderate"})
    res = results(r)
    assert res["SA-9"] == PASS and res["3.13.11"] == PASS and res["3.11.1"] == PASS
    assert r.decision == "CONDITIONAL"


def test_unknown_facts_are_never_pass():
    r = evaluate({"vendor": "X", "product": "Y", "users": "5"}, {})
    res = results(r)
    assert res["SR-6"] == FAIL  # no audit reports given
    assert res["3.4.9"] == COND and res["3.11.2"] == COND


def test_two_slides_rendered(tmp_path, monkeypatch):
    monkeypatch.setenv("AE_REPORT_DIR", str(tmp_path))
    out = server.ae_vendor_review(FIX["intake"], FIX["facts"])
    html = out["report_html"]
    assert html.count('class="slide"') == 2
    assert "Control results: 4 pass, 5 conditional, 3 fail for CUI" in html
    assert Path(out["report_path"]).exists()
    assert render_vendor_html(evaluate(FIX["intake"], FIX["facts"])).startswith("<!doctype html>")
