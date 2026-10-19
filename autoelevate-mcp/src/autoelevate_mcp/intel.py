"""Threat-intel lookups used by the pre-approval analysis.

- VirusTotal v3 file report by SHA-256 (needs VT_API_KEY)
- CISA Known Exploited Vulnerabilities catalog (public JSON feed, cached 12h)
- NVD CVE API 2.0 keyword search, filtered to CPEs that cover the requested version
  (NVD_API_KEY optional; raises the rate limit)
- endoflife.date lifecycle data for products mapped in policy.yaml

Every lookup returns a dict and never raises: a failed lookup becomes
{"status": "error", ...} so the analysis can mark that check for manual review.
"""

from __future__ import annotations

import os
import re
import time
from datetime import date
from typing import Any

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
EOL_URL = "https://endoflife.date/api/{}.json"

_kev_cache: dict[str, Any] = {"at": 0.0, "items": None}


def _norm(s: str | None) -> str:
    s = (s or "").lower()
    s = re.sub(r"\b(inc|llc|ltd|corp|corporation|co|n\.?v|b\.?v|gmbh|s\.?a|plc|usa|limited)\b\.?", " ", s)
    return re.sub(r"[^a-z0-9]+", " ", s).strip()


def parse_version(v: str | None) -> tuple[int, ...] | None:
    if not v:
        return None
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums[:4]) if nums else None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


class Intel:
    def __init__(self, http: httpx.Client | None = None) -> None:
        self.http = http or httpx.Client(timeout=30, follow_redirects=True)
        self.vt_key = os.environ.get("VT_API_KEY")
        self.nvd_key = os.environ.get("NVD_API_KEY")

    # ------------------------------------------------------------ VirusTotal
    def virustotal(self, sha256: str | None) -> dict:
        if not sha256:
            return {"status": "error", "detail": "Request has no SHA-256 hash."}
        if not self.vt_key:
            return {"status": "skipped", "detail": "VT_API_KEY not set."}
        try:
            r = self.http.get(VT_URL.format(sha256), headers={"x-apikey": self.vt_key})
            if r.status_code == 404:
                return {"status": "not_found", "detail": "Hash not known to VirusTotal."}
            r.raise_for_status()
            a = r.json()["data"]["attributes"]
            stats = a.get("last_analysis_stats", {})
            return {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": a.get("reputation"),
                "signers": (a.get("signature_info") or {}).get("signers"),
                "popular_threat_label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "detail": f"VirusTotal lookup failed: {e}"}

    # ------------------------------------------------------------------- KEV
    def _kev(self) -> list[dict]:
        if _kev_cache["items"] is None or time.time() - _kev_cache["at"] > 12 * 3600:
            r = self.http.get(KEV_URL)
            r.raise_for_status()
            _kev_cache.update(at=time.time(), items=r.json()["vulnerabilities"])
        return _kev_cache["items"]

    def kev_for_product(self, vendor: str | None, product: str | None) -> dict:
        try:
            nv, np_ = _norm(vendor), _norm(product)
            if not np_:
                return {"status": "error", "detail": "No product name to match."}
            vend_tokens = set(nv.split())
            hits = []
            for v in self._kev():
                kp, kv = _norm(v["product"]), _norm(v["vendorProject"])
                product_match = kp and (kp in np_ or np_ in kp)
                # KEV often lists the product as its own vendor (vendorProject "7-Zip").
                vendor_match = (not vend_tokens or bool(vend_tokens & set(kv.split()))
                                or kv == kp or (kv and kv in np_))
                if product_match and vendor_match:
                    hits.append({k: v.get(k) for k in ("cveID", "vendorProject", "product", "vulnerabilityName",
                                                        "dateAdded", "knownRansomwareCampaignUse")})
            return {"status": "ok", "hits": hits}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "detail": f"KEV lookup failed: {e}"}

    # ------------------------------------------------------------------- NVD
    def cves_for_version(self, product: str | None, version: str | None, max_results: int = 2000) -> dict:
        """CVEs whose NVD CPE configuration covers this product/version."""
        pv = parse_version(version)
        np_ = _norm(product)
        if not np_:
            return {"status": "error", "detail": "No product name to search NVD."}
        try:
            headers = {"apiKey": self.nvd_key} if self.nvd_key else {}
            r = self.http.get(NVD_URL, params={"keywordSearch": product, "resultsPerPage": max_results},
                              headers=headers)
            r.raise_for_status()
            data = r.json()
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "detail": f"NVD lookup failed: {e}"}

        prod_key = re.sub(r"[^a-z0-9]", "", np_)
        affecting, product_ids = [], []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            matched_product, covers = False, False
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        if not m.get("vulnerable"):
                            continue
                        parts = m["criteria"].split(":")
                        if len(parts) < 6 or parts[2] != "a":
                            continue
                        cpe_key = re.sub(r"[^a-z0-9]", "", parts[4])
                        if not cpe_key or not (cpe_key in prod_key or prod_key in cpe_key):
                            continue
                        matched_product = True
                        if pv is None:
                            continue
                        cpe_ver = parts[5]
                        if cpe_ver not in ("*", "-"):
                            cv = parse_version(cpe_ver)
                            if cv and _cmp(cv[:len(pv)], pv[:len(cv)]) == 0:
                                covers = True
                            continue
                        ok = True
                        for key, test in (("versionStartIncluding", lambda c: c >= 0),
                                          ("versionStartExcluding", lambda c: c > 0),
                                          ("versionEndIncluding", lambda c: c <= 0),
                                          ("versionEndExcluding", lambda c: c < 0)):
                            if key in m:
                                bound = parse_version(m[key])
                                if bound is None or not test(_cmp(pv, bound)):
                                    ok = False
                        has_bound = any(k in m for k in ("versionStartIncluding", "versionStartExcluding",
                                                         "versionEndIncluding", "versionEndExcluding"))
                        if ok and has_bound:
                            covers = True
            if matched_product:
                product_ids.append(cve["id"])
            if covers:
                affecting.append({"id": cve["id"], "cvss": _cvss(cve),
                                  "summary": cve["descriptions"][0]["value"][:200]})
        affecting.sort(key=lambda c: c["cvss"] or 0, reverse=True)
        return {"status": "ok", "product_cve_total": len(product_ids), "product_cve_ids": product_ids,
                "affecting_version": affecting,
                "version_checked": version}

    # ------------------------------------------------------------ lifecycle
    def end_of_life(self, slug: str, version: str | None) -> dict:
        pv = parse_version(version)
        try:
            r = self.http.get(EOL_URL.format(slug))
            if r.status_code == 404:
                return {"status": "unknown", "detail": f"endoflife.date has no '{slug}'."}
            r.raise_for_status()
            cycles = r.json()
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "detail": f"Lifecycle lookup failed: {e}"}
        if not pv:
            return {"status": "unknown", "detail": "No version to compare."}
        best = None
        for c in cycles:
            cv = parse_version(str(c.get("cycle")))
            if cv and pv[:len(cv)] == cv and (best is None or len(cv) > len(parse_version(str(best["cycle"])))):
                best = c
        if not best:
            return {"status": "unknown", "detail": f"Version {version} not matched to a {slug} release cycle."}
        eol = best.get("eol")
        is_eol = eol is True or (isinstance(eol, str) and date.fromisoformat(eol) <= date.today())
        return {"status": "ok", "product": slug, "cycle": best.get("cycle"), "eol": eol, "is_eol": is_eol,
                "latest": best.get("latest")}


def _cvss(cve: dict) -> float | None:
    m = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            return m[key][0]["cvssData"].get("baseScore")
    return None
