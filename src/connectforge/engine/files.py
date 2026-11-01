"""Reading connectors that tail a log file (syslog / CEF / key=value / regex lines)."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import List, Optional, Tuple

from connectforge.config.schema import ConnectorSpec
from connectforge.mapping import MappingError, parse_cef

# --- Files ----------------------------------------------------------------------------------------

_KV = re.compile(r'([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|\S*)')


def parse_line(line: str, spec: ConnectorSpec) -> Tuple[Optional[dict], Optional[str]]:
    f = spec.file
    try:
        if f.format == "cef":
            return parse_cef(line), None
        if f.format == "jsonl":
            obj = json.loads(line)
            return (obj, None) if isinstance(obj, dict) else (None, "JSON line is not an object")
        if f.format == "kv":
            pairs = {k: v[1:-1] if v.startswith('"') else v for k, v in _KV.findall(line)}
            return (pairs, None) if len(pairs) >= 2 else (None, "no key=value pairs found")
        if f.format == "regex":
            m = re.match(f.pattern, line)
            return (m.groupdict(), None) if m else (None, "line does not match pattern")
        row = next(csv.reader([line], delimiter=f.delimiter))
        if len(row) != len(f.columns):
            return None, f"expected {len(f.columns)} columns, got {len(row)}"
        return dict(zip(f.columns, row, strict=False)), None
    except (json.JSONDecodeError, re.error, csv.Error, MappingError) as e:
        return None, f"parse error: {e}"


def read_new_lines(path: Path, offset: int, max_bytes: int) -> Tuple[List[str], int, bool]:
    size = path.stat().st_size
    rotated = offset > size
    if rotated:
        offset = 0
    with path.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read(max_bytes)
    chunk = chunk[:chunk.rfind(b"\n") + 1]
    return chunk.decode("utf-8", "replace").splitlines(), offset + len(chunk), rotated
