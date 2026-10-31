"""Syslog receiver: lets push-only tools (firewalls, DLP appliances, on-prem SIEMs) feed the platform.

Devices send syslog (RFC 3164/5424, often carrying CEF) to UDP <port>. Each message is appended as one
line to data/feeds/syslog.log; file connectors tail that file and pick their vendor's lines with
`file.filter`. Writing to a file keeps the receiver tiny and gives replay/checkpointing for free.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

MAX_BYTES = 50 * 1024 * 1024  # rotate at 50 MB; tailing connectors detect the rotation


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, path: Path):
        self.path = path
        self.received = 0

    def datagram_received(self, data: bytes, addr) -> None:
        line = data.decode("utf-8", "replace").replace("\r", " ").replace("\n", " ").strip()
        if not line:
            return
        if self.path.exists() and self.path.stat().st_size > MAX_BYTES:
            self.path.replace(self.path.with_suffix(".log.1"))
        with self.path.open("a") as fh:
            fh.write(line[:8192] + "\n")
        self.received += 1


async def start_syslog(port: int, feeds_dir: Path, host: str = "0.0.0.0") -> Optional[asyncio.DatagramTransport]:
    feeds_dir.mkdir(parents=True, exist_ok=True)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: _SyslogProtocol(feeds_dir / "syslog.log"),
                                                       local_addr=(host, port))
    return transport
