"""Client for the AutoElevate admin portal API (apollo.autoelevate.com).

This is the same JSON API the msp.autoelevate.com web portal uses. It is not
published by CyberFOX, so endpoints can change without notice.

Auth: the portal signs in with email + password, then a TOTP code, and gets a
JWT back in the `authorization` response header. Tokens live 24 hours. The
token is sent back as a raw `Authorization` header (no "Bearer" prefix).
"""

from __future__ import annotations

import base64
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pyotp

API_BASE = "https://apollo.autoelevate.com/api"
CLIENT_NAME = "netrique-autoelevate-mcp"

# Rule scopes the API accepts. "msp" = All Companies; this server never sends it.
RULE_LEVELS = ("computer", "location", "company")
ELEVATION_TYPES = ("admin", "user")


class AutoElevateError(RuntimeError):
    pass


def _jwt_exp(token: str) -> float | None:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except Exception:
        return None


class AutoElevateClient:
    def __init__(
        self,
        email: str | None = None,
        password: str | None = None,
        totp_secret: str | None = None,
        token: str | None = None,
        base_url: str = API_BASE,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.email = email or os.environ.get("AE_EMAIL")
        self.password = password or os.environ.get("AE_PASSWORD")
        self.totp_secret = totp_secret or os.environ.get("AE_TOTP_SECRET")
        self._token = token or os.environ.get("AE_TOKEN")
        self._http = httpx.Client(base_url=base_url, timeout=60, transport=transport)

    # ------------------------------------------------------------------ auth
    def _headers(self, version: str | None, auth: bool = True) -> dict[str, str]:
        h = {
            "X-Client-Name": CLIENT_NAME,
            "Accept": f"application/vnd.autoelevate.{version}+json" if version else "application/json",
            "Content-Type": "application/json",
        }
        if auth:
            h["Authorization"] = self._ensure_token()
        return h

    def _ensure_token(self) -> str:
        if self._token:
            exp = _jwt_exp(self._token)
            if exp is None or exp - time.time() > 300:
                return self._token
        self._token = self._login()
        return self._token

    def _login(self) -> str:
        if not (self.email and self.password):
            raise AutoElevateError(
                "No valid AutoElevate token. Set AE_EMAIL, AE_PASSWORD and AE_TOTP_SECRET "
                "for a portal user with a local password (Entra SSO users can't sign in here), "
                "or set AE_TOKEN to a current portal token."
            )
        r = self._http.post(
            "/users/login",
            headers=self._headers("v2", auth=False),
            json={"email": self.email, "password": self.password},
        )
        if r.status_code >= 400:
            raise AutoElevateError(f"AutoElevate login failed ({r.status_code}): {r.text[:300]}")
        data = r.json()
        direct = r.headers.get("authorization")
        if direct and not data.get("token"):
            return direct
        mfa_token = data.get("token")
        if not mfa_token:
            raise AutoElevateError("AutoElevate login returned no token.")
        if not self.totp_secret:
            raise AutoElevateError("AutoElevate requires a 2FA code. Set AE_TOTP_SECRET for the service user.")
        body = {"mfaToken": mfa_token, "code": pyotp.TOTP(self.totp_secret).now()}
        if data.get("otpSecret"):  # first-time 2FA setup on this account
            body["otpSecret"] = data["otpSecret"]
        r = self._http.post("/users/adminPortalOtpVerify", headers=self._headers(None, auth=False), json=body)
        token = r.headers.get("authorization")
        if r.status_code >= 400 or not token:
            raise AutoElevateError(f"AutoElevate 2FA verification failed ({r.status_code}): {r.text[:300]}")
        return token

    # --------------------------------------------------------------- request
    def _call(self, method: str, url: str, version: str | None = None, **kw: Any) -> Any:
        r = self._http.request(method, url, headers=self._headers(version), **kw)
        if r.status_code == 401 and (self.email and self.password):
            self._token = None
            r = self._http.request(method, url, headers=self._headers(version), **kw)
        if r.status_code >= 400:
            raise AutoElevateError(f"{method} {url} failed ({r.status_code}): {r.text[:300]}")
        return r.json() if r.content else None

    def _paged(self, url: str, version: str, params: dict[str, Any], limit: int) -> list[dict]:
        out: list[dict] = []
        skip, take = 0, min(100, limit)
        while len(out) < limit:
            p = {k: v for k, v in {**params, "take": take, "skip": skip}.items() if v is not None}
            data = self._call("GET", url, version, params=p)
            items = data.get("items", [])
            out.extend(items)
            if not items or len(out) >= data.get("totalCount", 0):
                break
            skip += len(items)
        return out[:limit]

    # ------------------------------------------------------------------ data
    def list_companies(self) -> list[dict]:
        return self._paged("/companies", "v2", {}, 1000)

    def list_requests(self, days: int = 7, company_id: str | None = None, limit: int = 200) -> list[dict]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        return self._paged(
            "/requests", "v3",
            {"start": start.isoformat(), "end": end.isoformat(), "companyId": company_id},
            limit,
        )

    def get_request(self, request_id: str) -> dict:
        data = self._call("GET", f"/requests/{request_id}", "v2")
        req = data.get("request", data)
        if data.get("company"):
            req["company"] = data["company"]
        return req

    def request_id_for_ticket(self, ticket_id: int | str) -> str:
        return self._call("GET", "/requests/getIdByTicketId", params={"ticketId": ticket_id})["id"]

    def list_rules(self, company_id: str | None = None, limit: int = 2000) -> list[dict]:
        return self._paged("/rules", "v4", {"companyId": company_id}, limit)

    def list_computers(self, company_id: str | None = None, limit: int = 2000) -> list[dict]:
        return self._paged("/computers", "v2", {"companyId": company_id}, limit)

    def decide_request(
        self,
        request_id: str,
        decision: str,
        create_rule: bool = False,
        rule_level: str | None = None,
        elevation_type: str | None = None,
        duration_minutes: int | None = None,
        denial_reason: str | None = None,
    ) -> dict:
        if decision not in ("approve", "deny"):
            raise ValueError("decision must be 'approve' or 'deny'")
        if rule_level is not None and rule_level not in RULE_LEVELS:
            raise ValueError(f"rule_level must be one of {RULE_LEVELS}")
        body: dict[str, Any] = {
            "createRule": create_rule,
            "ruleLevel": rule_level,
            "elevationType": elevation_type,
            "durationInMinutes": duration_minutes,
        }
        if decision == "deny" and denial_reason:
            body["denialReason"] = denial_reason
        return self._call("POST", f"/requests/{request_id}/{decision}", json=body)
