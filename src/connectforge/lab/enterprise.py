"""Lab imitations of enterprise vendor API *patterns* (not their data), so every platform feature can be
demonstrated and tested offline:

  /prisma   token exchange: POST JSON credentials -> token in body -> custom header   (Prisma Cloud style)
  /fmc      token exchange: basic auth -> token in a response HEADER                    (Cisco FMC style)
  /zia      session cookie after an obfuscated-API-key login                           (Zscaler ZIA style)
  /sophos   OAuth2 -> whoami discovery -> region host + X-Tenant-ID, cursor + has_more   (Sophos Central style)
  /wiz      OAuth2 with `audience`, credentials in body -> GraphQL with nested cursor   (Wiz style)
  /google   service-account JWT (RS256) -> access token -> pageToken                    (Google SCC style)
  /cortex   advanced API key hash headers, offsets inside request_data                  (Cortex XSIAM style)
  /xmlfw    XML response                                                                (Sophos Firewall style)

Plus a syslog sender that emits CEF (Check Point style) and Juniper RT_FLOW lines to the platform's
UDP syslog receiver. All values are synthetic (RFC 5737 IPs, .example domains).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import APIRouter, Form, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from connectforge.security.auth import zscaler_obfuscated_key

router = APIRouter()

PRISMA_KEY, PRISMA_SECRET = "prisma-access-key-id", "prisma-secret-key-123"
FMC_USER, FMC_PASS = "fmc-api", "fmc-pass-456"
ZIA_KEY, ZIA_USER, ZIA_PASS = "AbCdEfGhIjKlMnOpQrStUvWxYz012345", "admin@acme.example", "zia-pass-789"
OAUTH_ID, OAUTH_SECRET = "lab-client-id", "lab-client-secret"
CORTEX_KEY, CORTEX_KEY_ID = "cortex-advanced-key-abcdef0123456789", "7"

_now = datetime.now(timezone.utc).replace(microsecond=0)
_tokens: dict = {}


def _issue(kind: str) -> str:
    tok = f"{kind}-" + hashlib.sha256(f"{kind}{time.time()}".encode()).hexdigest()[:24]
    _tokens[tok] = kind
    return tok


def _need(token: Optional[str], kind: str) -> None:
    if not token or _tokens.get(token) != kind:
        raise HTTPException(401, {"error": "invalid or expired token"})


# --- Google: generate a lab service-account key; tests load it as the secret ----------------------------

def _lab_google_key():
    """One persistent lab key (data/lab/), so the mock process and the vault seeding agree across restarts."""
    path = os.path.join(os.environ.get("CF_DATA_DIR", "data"), "lab", "google_lab_key.pem")
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    os.chmod(path, 0o600)
    return key


_GKEY = _lab_google_key()
GOOGLE_KEY_JSON = json.dumps({
    "type": "service_account", "project_id": "lab-project", "private_key_id": "lab-key-1",
    "client_email": "connectforge@lab-project.iam.gserviceaccount.com",
    "private_key": _GKEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()).decode(),
    "token_uri": "http://127.0.0.1:9100/google/token",
})


# --- Prisma-style token exchange -------------------------------------------------------------------------


@router.post("/prisma/login")
async def prisma_login(request: Request):
    body = await request.json()
    if body.get("username") != PRISMA_KEY or body.get("password") != PRISMA_SECRET:
        raise HTTPException(401, {"message": "invalid credentials"})
    return {"token": _issue("prisma"), "message": "login_successful"}


@router.get("/prisma/v2/alert")
def prisma_alerts(pageToken: Optional[str] = None, limit: int = 50, x_redlock_auth: Optional[str] = Header(None)):
    _need(x_redlock_auth, "prisma")
    alerts = [{"id": f"P-{1000 + i}", "status": "open", "alertTime": int((_now - timedelta(minutes=7 * i)).timestamp() * 1000),
               "policy": {"name": ["Public S3 bucket", "Root account used", "Security group allows 0.0.0.0/0"][i % 3],
                          "severity": ["high", "critical", "medium"][i % 3]},
               "resource": {"name": f"res-{i}", "cloudType": "aws"}} for i in range(80)]
    start = int(pageToken or 0)
    out = {"items": alerts[start:start + limit], "totalRows": len(alerts)}
    if start + limit < len(alerts):
        out["nextPageToken"] = str(start + limit)
    return out


# --- Cisco FMC-style: token in a response header -----------------------------------------------------------


@router.post("/fmc/api/fmc_platform/v1/auth/generatetoken")
def fmc_token(authorization: Optional[str] = Header(None)):
    expected = "Basic " + base64.b64encode(f"{FMC_USER}:{FMC_PASS}".encode()).decode()
    if authorization != expected:
        raise HTTPException(401, "bad credentials")
    return Response(status_code=204, headers={"X-auth-access-token": _issue("fmc"), "DOMAIN_UUID": "e276abec"})


@router.get("/fmc/api/fmc_config/v1/domain/e276abec/devices/devicerecords")
def fmc_devices(offset: int = 0, limit: int = 25, x_auth_access_token: Optional[str] = Header(None)):
    _need(x_auth_access_token, "fmc")
    devices = [{"id": f"dev-{i:04d}", "name": f"FTD-{i:02d}", "hostName": f"10.10.{i // 50}.{i % 50 + 1}",
                "model": "Cisco Firepower 2130", "sw_version": "7.4.1", "healthStatus": ["green", "yellow"][i % 7 == 3]}
               for i in range(60)]
    return {"items": devices[offset:offset + limit], "paging": {"offset": offset, "limit": limit, "count": len(devices)}}


# --- Zscaler-style: obfuscated key -> session cookie -----------------------------------------------------


@router.post("/zia/api/v1/authenticatedSession")
async def zia_login(request: Request):
    b = await request.json()
    ts = str(b.get("timestamp", ""))
    if b.get("username") != ZIA_USER or b.get("password") != ZIA_PASS or not ts.isdigit() or \
            b.get("apiKey") != zscaler_obfuscated_key(ZIA_KEY, ts):
        raise HTTPException(401, {"code": "AUTHENTICATION_FAILED"})
    resp = JSONResponse({"authType": "ADMIN_LOGIN", "obfuscateApiKey": True})
    resp.set_cookie("JSESSIONID", _issue("zia"), httponly=True)
    return resp


@router.get("/zia/api/v1/users")
def zia_users(request: Request, page: int = 1, pageSize: int = 100):
    _need(request.cookies.get("JSESSIONID"), "zia")
    users = [{"id": 5000 + i, "name": f"User {i}", "email": f"user{i}@acme.example",
              "department": {"name": ["Finance", "Engineering"][i % 2]}, "deleted": i % 17 == 0} for i in range(130)]
    return users[(page - 1) * pageSize: page * pageSize]


# --- OAuth2 token endpoint (Sophos / Wiz styles) -------------------------------------------------------------


@router.post("/oauth/token")
async def oauth_token(request: Request, authorization: Optional[str] = Header(None)):
    form = await request.form()
    basic = "Basic " + base64.b64encode(f"{OAUTH_ID}:{OAUTH_SECRET}".encode()).decode()
    body_ok = form.get("client_id") == OAUTH_ID and form.get("client_secret") == OAUTH_SECRET
    if not (authorization == basic or body_ok) or form.get("grant_type") != "client_credentials":
        raise HTTPException(401, {"error": "invalid_client"})
    kind = "wiz" if form.get("audience") == "wiz-api" else "sophos"
    return {"access_token": _issue(kind), "expires_in": 3600, "token_type": "Bearer"}


@router.get("/sophos/whoami/v1")
def sophos_whoami(request: Request, authorization: Optional[str] = Header(None)):
    _need((authorization or "").removeprefix("Bearer "), "sophos")
    return {"id": "tenant-8f2e", "idType": "tenant",
            "apiHosts": {"global": str(request.base_url).rstrip("/") + "/sophos",
                         "dataRegion": str(request.base_url).rstrip("/") + "/sophos-region"}}


@router.get("/sophos-region/siem/v1/alerts")
def sophos_alerts(cursor: Optional[str] = None, limit: int = 40, authorization: Optional[str] = Header(None),
                  x_tenant_id: Optional[str] = Header(None)):
    _need((authorization or "").removeprefix("Bearer "), "sophos")
    if x_tenant_id != "tenant-8f2e":
        raise HTTPException(400, {"error": "X-Tenant-ID header required"})
    alerts = [{"id": f"sa-{i}", "type": ["Event::Endpoint::Threat::Detected", "Event::Endpoint::UpdateFailure"][i % 2],
               "severity": ["high", "low"][i % 2], "when": (_now - timedelta(minutes=3 * i)).isoformat(),
               "description": f"Threat detected on WS-{i:03d}", "location": f"WS-{i:03d}"} for i in range(95)]
    start = int(cursor or 0)
    has_more = start + limit < len(alerts)
    return {"items": alerts[start:start + limit], "has_more": has_more, "next_cursor": str(start + limit) if has_more else None}


@router.post("/wiz/graphql")
async def wiz_graphql(request: Request, authorization: Optional[str] = Header(None)):
    _need((authorization or "").removeprefix("Bearer "), "wiz")
    body = await request.json()
    if "issues" not in body.get("query", ""):
        raise HTTPException(400, {"errors": [{"message": "unknown query"}]})
    variables = body.get("variables", {})
    first, after = int(variables.get("first", 50)), int(variables.get("after") or 0)
    nodes = [{"id": f"wiz-issue-{i}", "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4], "status": "OPEN",
              "createdAt": (_now - timedelta(hours=i)).isoformat().replace("+00:00", "Z"),
              "sourceRule": {"name": ["Exposed VM with critical CVE", "Admin role without MFA"][i % 2]},
              "entitySnapshot": {"name": f"vm-prod-{i}", "type": "VIRTUAL_MACHINE"}} for i in range(120)]
    page = nodes[after:after + first]
    return {"data": {"issues": {"nodes": page, "pageInfo": {"hasNextPage": after + first < len(nodes),
                                                            "endCursor": str(after + first)}}}}


# --- Google service account ------------------------------------------------------------------------------


def _b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


@router.post("/google/token")
def google_token(grant_type: str = Form(...), assertion: str = Form(...)):
    try:
        header, claims, sig = assertion.split(".")
        _GKEY.public_key().verify(_b64d(sig), f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
        c = json.loads(_b64d(claims))
    except Exception as e:
        raise HTTPException(400, {"error": "invalid_grant", "error_description": f"bad JWT: {type(e).__name__}"}) from e
    if grant_type != "urn:ietf:params:oauth:grant-type:jwt-bearer" or c["exp"] < time.time():
        raise HTTPException(400, {"error": "invalid_grant"})
    return {"access_token": _issue("google"), "expires_in": 3599, "token_type": "Bearer"}


@router.get("/google/v2/organizations/123/sources/-/findings")
def google_findings(pageToken: Optional[str] = None, pageSize: int = 50, authorization: Optional[str] = Header(None)):
    _need((authorization or "").removeprefix("Bearer "), "google")
    results = [{"finding": {"name": f"organizations/123/sources/9/findings/f{i}", "category": ["OPEN_FIREWALL", "PUBLIC_BUCKET_ACL"][i % 2],
                            "severity": ["HIGH", "MEDIUM"][i % 2], "eventTime": (_now - timedelta(hours=i)).isoformat().replace("+00:00", "Z"),
                            "description": "Lab finding", "resourceName": f"//compute.googleapis.com/projects/lab/instances/vm-{i}"}}
               for i in range(70)]
    start = int(pageToken or 0)
    out = {"listFindingsResults": results[start:start + pageSize], "totalSize": len(results)}
    if start + pageSize < len(results):
        out["nextPageToken"] = str(start + pageSize)
    return out


# --- Cortex advanced key ---------------------------------------------------------------------------------


@router.post("/cortex/public_api/v1/alerts/get_alerts_multi_events")
async def cortex_alerts(request: Request):
    h = request.headers
    ts, nonce = h.get("x-xdr-timestamp", ""), h.get("x-xdr-nonce", "")
    expected = hashlib.sha256(f"{CORTEX_KEY}{nonce}{ts}".encode()).hexdigest()
    if h.get("x-xdr-auth-id") != CORTEX_KEY_ID or h.get("authorization") != expected or len(nonce) < 32:
        raise HTTPException(401, {"reply": {"err_msg": "Public API request unauthorized"}})
    rd = (await request.json()).get("request_data", {})
    start, end = int(rd.get("search_from", 0)), int(rd.get("search_to", 100))
    alerts = [{"alert_id": str(9000 + i), "name": ["Behavioral Threat", "WildFire Malware"][i % 2],
               "severity": ["high", "medium"][i % 2], "detection_timestamp": int((_now - timedelta(minutes=11 * i)).timestamp() * 1000),
               "host_name": f"WS-{i:03d}", "host_ip": [f"10.0.1.{i + 10}"], "description": "Lab alert"} for i in range(150)]
    return {"reply": {"total_count": len(alerts), "result_count": len(alerts[start:end]), "alerts": alerts[start:end]}}


# --- XML firewall API --------------------------------------------------------------------------------------


@router.get("/xmlfw/webconsole/APIController")
def xml_firewall(reqxml: str = ""):
    if "<Login><Username>fwapi</Username>" not in reqxml:
        return Response('<?xml version="1.0"?><Response><Login><status>Authentication Failure</status></Login></Response>',
                        media_type="application/xml")
    rows = "".join(f"<Event id='e{i}'><Time>{(_now - timedelta(minutes=i)).isoformat()}</Time><Rule>{['Block RDP', 'Allow web'][i % 2]}</Rule>"
                   f"<SrcIP>{['203.0.113.45', '10.0.1.20'][i % 2]}</SrcIP><DstIP>10.0.2.11</DstIP><DstPort>{[3389, 443][i % 2]}</DstPort>"
                   f"<Action>{['Deny', 'Accept'][i % 2]}</Action></Event>" for i in range(30))
    return Response(f'<?xml version="1.0"?><Response APIVersion="1905.1"><Login><status>Authentication Successful</status></Login>'
                    f"<Events>{rows}<Event id='bad'><Time>not-a-time</Time></Event></Events></Response>", media_type="application/xml")


# --- syslog sender (Check Point CEF + Juniper RT_FLOW) ----------------------------------------------------


def syslog_lines(i: int) -> list:
    t = datetime.now(timezone.utc)
    deny = i % 3 == 0
    return [
        f"<134>{t:%b %d %H:%M:%S} cp-gw01 CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|{'Drop' if deny else 'Accept'}|"
        f"{'Drop' if deny else 'Accept'}|{5 if deny else 2}|rt={int(t.timestamp() * 1000)} src={'203.0.113.45' if deny else '10.0.1.22'} "
        f"dst=10.0.2.11 dpt={3389 if deny else 443} proto=6 act={'Drop' if deny else 'Accept'} cs1Label=Rule cs1=Block RDP from internet "
        f"externalId=cp-{int(t.timestamp())}-{i}",
        f"<14>1 {t.isoformat()} srx-edge01 RT_FLOW - RT_FLOW_SESSION_{'DENY' if deny else 'CREATE'} - "
        f"source-address=\"{'198.51.100.9' if deny else '10.0.1.30'}\" source-port=\"{40000 + i}\" destination-address=\"10.0.2.10\" "
        f"destination-port=\"{22 if deny else 53}\" protocol-id=\"6\" policy-name=\"{'deny-ssh' if deny else 'allow-dns'}\"",
    ]


async def syslog_sender(target_port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    i = 0
    while True:
        for line in syslog_lines(i):
            sock.sendto(line.encode(), ("127.0.0.1", target_port))
        if i % 20 == 19:
            sock.sendto(b"<134>garbage line with CEF:0|broken", ("127.0.0.1", target_port))
        i += 1
        await asyncio.sleep(3)


def start_syslog_sender() -> Optional[asyncio.Task]:
    port = os.environ.get("MOCK_SYSLOG_TARGET_PORT")
    return asyncio.create_task(syslog_sender(int(port))) if port else None
