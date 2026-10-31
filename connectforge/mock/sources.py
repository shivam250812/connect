"""Lab sources for failure drills and offline demos (the real connectors call real APIs).

    uvicorn connectforge.mock.sources:app --port 9100

* Okta users       — GET /okta/api/v1/users, `SSWS` token, Link-header pagination, 429 + Retry-After,
                     records with missing / malformed fields.               -> users table
* EDR devices      — GET /edr/api/devices, API key in X-API-Key header, offset pagination.  -> devices table
* AWS CloudTrail   — POST /aws/ (LookupEvents), SigV4-verified, NextToken, nested JSON, 503s. -> events
* FortiGate        — appends key=value traffic logs to data/feeds/fortigate.log.            -> events

Chaos switches: POST /mock/chaos {"source": "okta"|"edr"|"aws", "mode": "normal"|"outage"|"evil_link"}.
All data is synthetic: RFC 5737 IPs, example.com identities.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from ..auth import sigv4_headers

OKTA_TOKEN = os.environ.get("MOCK_OKTA_TOKEN", "okta-demo-token-7f3a9c")
AWS_KEY_ID = os.environ.get("MOCK_AWS_KEY_ID", "AKIAMOCKDEMO0000001")
AWS_SECRET = os.environ.get("MOCK_AWS_SECRET", "mock/Secret+Key/For/Demo/Only/0000000000")
EDR_KEY = os.environ.get("MOCK_EDR_KEY", "edr-demo-key-31c9")
FEED_DIR = Path(os.environ.get("MOCK_FEED_DIR", "data/feeds"))

START = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=50)
USERS = ["priya.sharma", "rohan.verma", "ananya.iyer", "arjun.mehta", "kavya.nair", "adm.rahul", "svc-deploy"]
CHAOS = {"okta": "normal", "aws": "normal", "edr": "normal"}
COUNTERS = {"okta": 0, "aws": 0, "edr": 0}


def _rng(*parts) -> random.Random:
    return random.Random(int(hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:12], 16))


def _uid(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def _series(step_seconds: int):
    """Indices of events that exist 'so far' (a new one every step_seconds since START)."""
    n = int((datetime.now(timezone.utc) - START).total_seconds() // step_seconds) + 1
    return range(n)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from .enterprise import start_syslog_sender

    FEED_DIR.mkdir(parents=True, exist_ok=True)
    tasks = [asyncio.create_task(_fortigate_writer()), start_syslog_sender()]
    yield
    for t in tasks:
        if t:
            t.cancel()


app = FastAPI(title="ConnectForge — mock sources", lifespan=lifespan)


def _include_enterprise() -> None:
    from .enterprise import router

    app.include_router(router)


# --- Okta users -------------------------------------------------------------------------------

FIRST = ["Priya", "Rohan", "Ananya", "Arjun", "Kavya", "Vikram", "Neha", "Aditya", "Sneha", "Rahul", "Isha", "Karan"]
LAST = ["Sharma", "Verma", "Iyer", "Mehta", "Nair", "Singh", "Gupta", "Rao", "Patel", "Desai", "Kapoor", "Malhotra"]


def okta_user(i: int) -> dict:
    r = _rng("okta-user", i)
    first, last = FIRST[i % len(FIRST)], LAST[(i * 7) % len(LAST)]
    login = f"{first}.{last}{i}@acme.example".lower()
    user = {
        "id": "00u" + _uid("okta", i)[:17],
        "status": r.choice(["ACTIVE", "ACTIVE", "ACTIVE", "SUSPENDED", "DEPROVISIONED", "PROVISIONED"]),
        "created": (START - timedelta(days=400 - i)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastLogin": (START - timedelta(hours=r.randint(1, 900))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "profile": {"firstName": first, "lastName": last, "login": login, "email": login,
                    "title": r.choice(["Analyst", "Engineer", "Manager", "Accountant"]),
                    "department": r.choice(["Finance", "Engineering", "Security", "HR"])},
    }
    if i % 29 == 7:
        del user["id"]                      # malformed: no id
    if i % 31 == 11:
        user["lastLogin"] = "yesterday"     # malformed: not a date
    return user


def _count(source: str) -> int:
    COUNTERS[source] += 1
    return COUNTERS[source]


@app.get("/okta/api/v1/users")
def okta_users(request: Request, limit: int = 200, after: int = 0, authorization: Optional[str] = Header(None)):
    if authorization != f"SSWS {OKTA_TOKEN}":
        raise HTTPException(401, {"errorCode": "E0000011", "errorSummary": "Invalid token provided"})
    n = _count("okta")
    if CHAOS["okta"] == "outage":
        raise HTTPException(503, "Service Unavailable")
    if n % 3 == 0:  # Okta-style rate limit: 429 + Retry-After + X-Rate-Limit-Reset
        reset = int(datetime.now(timezone.utc).timestamp()) + 1
        return JSONResponse({"errorCode": "E0000047", "errorSummary": "API call exceeded rate limit"},
                            status_code=429, headers={"Retry-After": "1", "X-Rate-Limit-Reset": str(reset)})
    users = [okta_user(i) for i in range(140)]
    page = users[after:after + limit]
    headers = {}
    if after + limit < len(users):
        base = "http://evil.example/okta/api/v1/users" if CHAOS["okta"] == "evil_link" else str(request.url_for("okta_users"))
        headers["Link"] = f'<{base}?limit={limit}&after={after + limit}>; rel="next"'
    return JSONResponse(page, headers=headers)


# --- EDR devices ----------------------------------------------------------------------------------


def edr_device(i: int) -> dict:
    r = _rng("edr", i)
    os_name = r.choice(["Windows 11 23H2", "Windows 10 22H2", "macOS 15.1", "Ubuntu 24.04", "Windows Server 2022"])
    d = {"device_id": "dev-" + _uid("edr", i)[:10],
         "hostname": f"{'SRV' if 'Server' in os_name else 'WS'}-{i + 1:03d}",
         "local_ip": f"10.0.{1 + i // 200}.{10 + i % 200}",
         "os_name": os_name, "assigned_user": f"{FIRST[i % len(FIRST)].lower()}.{LAST[(i * 7) % len(LAST)].lower()}",
         "agent_status": r.choice(["online", "online", "online", "offline", "isolated"]),
         "last_contact": int((datetime.now(timezone.utc) - timedelta(minutes=r.randint(1, 4000))).timestamp() * 1000),
         "mac": ":".join(f"{r.randint(0, 255):02x}" for _ in range(6))}
    if i % 37 == 5:
        d["local_ip"] = "10.0.1.300"        # malformed IP
    return d


@app.get("/edr/api/devices")
def edr_devices(offset: int = 0, limit: int = 50, x_api_key: Optional[str] = Header(None)):
    if x_api_key != EDR_KEY:
        raise HTTPException(401, {"error": "invalid API key"})
    _count("edr")
    if CHAOS["edr"] == "outage":
        raise HTTPException(503, "Service Unavailable")
    devices = [edr_device(i) for i in range(230)]
    return {"total": len(devices), "offset": offset, "items": devices[offset:offset + min(limit, 100)]}


# --- AWS CloudTrail ------------------------------------------------------------------------------

CT_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"


def cloudtrail_event(i: int) -> dict:
    r = _rng("aws", i)
    ts = START + timedelta(seconds=45 * i)
    name, ro = r.choice([("ConsoleLogin", "false"), ("AssumeRole", "true"), ("GetObject", "true"),
                         ("DescribeInstances", "true"), ("PutBucketPolicy", "false"), ("CreateAccessKey", "false")])
    if i % 29 == 11:
        name, ro = "StopLogging", "false"
    user = r.choice(["adm.rahul", "svc-deploy", "ci-runner", "priya.sharma"])
    detail = {
        "eventVersion": "1.09", "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventName": name,
        "eventSource": "s3.amazonaws.com" if name.endswith(("Object", "Policy")) else "iam.amazonaws.com",
        "awsRegion": r.choice(["ap-south-1", "ap-south-1", "us-east-1"]),
        "sourceIPAddress": "198.51.100.77" if name in ("CreateAccessKey", "StopLogging") else "10.20.0.15",
        "userAgent": "aws-cli/2.17 Python/3.12",
        "userIdentity": {"type": "IAMUser", "userName": user, "accountId": "111122223333",
                         "arn": f"arn:aws:iam::111122223333:user/{user}"},
        "errorCode": "AccessDenied" if r.random() < 0.1 else None,
    }
    blob = json.dumps(detail)
    if i % 19 == 3:
        blob = blob[:40]  # malformed: truncated embedded JSON
    return {"EventId": _uid("aws", i), "EventName": name, "ReadOnly": ro, "Username": user,
            "EventTime": ts.timestamp(), "EventSource": detail["eventSource"], "CloudTrailEvent": blob}


def _verify_sigv4(request: Request, body: bytes) -> None:
    auth = request.headers.get("authorization", "")
    m = re.match(r"AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request, "
                 r"SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$", auth)
    if not m or m.group(1) != AWS_KEY_ID:
        raise HTTPException(403, {"__type": "UnrecognizedClientException", "message": "invalid credentials"})
    amz_date = request.headers.get("x-amz-date", "")
    when = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    if abs((datetime.now(timezone.utc) - when).total_seconds()) > 300:
        raise HTTPException(403, {"__type": "InvalidSignatureException", "message": "Signature expired"})
    signed = [h for h in m.group(5).split(";") if h not in ("host", "x-amz-date")]
    expected = sigv4_headers(request.method, str(request.url), {h: request.headers[h] for h in signed}, body,
                             AWS_KEY_ID, AWS_SECRET, m.group(3), m.group(4), now=when)["Authorization"]
    if expected.rsplit("Signature=", 1)[1] != m.group(6):
        raise HTTPException(403, {"__type": "InvalidSignatureException", "message": "signature mismatch"})


@app.post("/aws/")
async def cloudtrail(request: Request):
    body = await request.body()
    if request.headers.get("x-amz-target") != CT_TARGET:
        raise HTTPException(400, {"__type": "UnknownOperationException"})
    _verify_sigv4(request, body)
    n = _count("aws")
    if CHAOS["aws"] == "outage" or n % 5 == 0:
        return JSONResponse({"__type": "ServiceUnavailableException"}, status_code=503)
    args = json.loads(body or b"{}")
    start = float(args.get("StartTime", START.timestamp()))
    page_size = min(int(args.get("MaxResults", 50)), 50)
    offset = int(args.get("NextToken") or 0)
    events = [cloudtrail_event(i) for i in _series(45)]
    events = [e for e in events if e["EventTime"] >= start]
    events.sort(key=lambda e: -e["EventTime"])  # CloudTrail returns newest first
    page = events[offset:offset + page_size]
    out = {"Events": page}
    if offset + page_size < len(events):
        out["NextToken"] = str(offset + page_size)
    return out


# --- FortiGate log writer -------------------------------------------------------------------------


def fortigate_line(i: int, ts: datetime) -> str:
    r = _rng("fgt", i)
    if i % 25 == 24:
        return "%%%% FGT-HQ-01 log buffer overflow \x00\x00 truncated"
    deny = i % 6 == 0
    src = "203.0.113.45" if deny else f"10.0.1.{r.randint(10, 40)}"
    dst, port, svc = (("10.0.2.11", 3389, "RDP") if deny else
                      r.choice([("198.51.100.20", 443, "HTTPS"), ("198.51.100.31", 443, "HTTPS"), ("10.0.2.10", 53, "DNS")]))
    return (f'date={ts:%Y-%m-%d} time={ts:%H:%M:%S} devname="FGT-HQ-01" devid="FG100FTK0000001" '
            f'logid="0000000013" type="traffic" subtype="forward" level="{"warning" if deny else "notice"}" '
            f'srcip={src} srcport={r.randint(1024, 65000)} srcintf="{"wan1" if deny else "lan"}" '
            f'dstip={dst} dstport={port} dstintf="{"lan" if deny else "wan1"}" proto=6 '
            f'action="{"deny" if deny else "accept"}" service="{svc}" sentbyte={0 if deny else r.randint(500, 900000)} '
            f'rcvdbyte={0 if deny else r.randint(200, 90000)} policyid={99 if deny else 12}')


async def _fortigate_writer() -> None:
    path = FEED_DIR / "fortigate.log"
    i = 0
    if not path.exists() or path.stat().st_size == 0:
        with path.open("a") as fh:
            for i in range(60):
                fh.write(fortigate_line(i, START + timedelta(seconds=30 * i)) + "\n")
    i = sum(1 for _ in path.open())
    while True:
        await asyncio.sleep(2)
        with path.open("a") as fh:
            for _ in range(3):
                fh.write(fortigate_line(i, datetime.now(timezone.utc)) + "\n")
                i += 1


@app.post("/mock/chaos")
async def chaos(request: Request):
    body = await request.json()
    if body.get("source") not in CHAOS or body.get("mode") not in ("normal", "outage", "evil_link"):
        raise HTTPException(400, "source in okta|aws|edr, mode in normal|outage|evil_link")
    CHAOS[body["source"]] = body["mode"]
    return CHAOS


@app.get("/mock/status")
def status():
    return {"chaos": CHAOS, "requests": COUNTERS}


_include_enterprise()
