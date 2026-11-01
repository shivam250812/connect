"""Paging through a source (FR-3) and incremental sync checkpoints (B-1)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, List, Optional
from urllib.parse import urljoin

from connectforge.config.schema import ConnectorSpec, CursorSpec
from connectforge.engine.errors import FetchError
from connectforge.engine.http import Fetcher
from connectforge.mapping import (
    MappingError,
    find_next,
    find_records,
    get_path,
    parse_datetime,
    set_path,
    xml_to_dict,
)


def format_cursor(dt: datetime, spec: CursorSpec) -> Any:
    dt = dt.astimezone(timezone.utc)
    if spec.format == "epoch":
        value: Any = int(dt.timestamp())
    elif spec.format == "epoch_ms":
        value = int(dt.timestamp() * 1000)
    elif spec.format == "date":
        value = dt.strftime("%Y-%m-%d")
    elif spec.format == "iso":
        value = dt.isoformat()
    else:
        value = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
    return spec.template.replace("{value}", str(value)) if spec.template != "{value}" else value


def initial_cursor(spec: CursorSpec) -> datetime:
    m = re.fullmatch(r"-(\d+)([smhd])", spec.initial.strip())
    if m:
        unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
        return datetime.now(timezone.utc) - timedelta(**{unit: int(m.group(1))})
    return parse_datetime(spec.initial)


async def fetch_pages(spec: ConnectorSpec, fetcher: Fetcher, cursor: Optional[datetime]) -> AsyncIterator[List[Any]]:
    """Pagination (FR-3): link header, next URL, next token, page number or offset."""
    req, p = spec.request, spec.pagination
    token_path, token_param = p.token_path, p.token_param
    url = req.base_url.rstrip("/") + ("/" + req.path.lstrip("/") if req.path else "")
    params = dict(req.params)
    body = json.loads(json.dumps(req.body)) if req.body is not None else None  # deep copy: never mutate the spec
    if req.method == "POST" and body is None:
        body = {}

    def put(where: str, key: str, value: Any) -> None:
        if where == "body" and body is not None:
            set_path(body, key, value)  # nested paths: request_data.search_from, variables.after
        else:
            params[key] = value

    if spec.cursor and cursor is not None:
        put(spec.cursor.param_in, spec.cursor.param, format_cursor(cursor, spec.cursor))
        if spec.cursor.end_param:
            put(spec.cursor.param_in, spec.cursor.end_param, format_cursor(datetime.now(timezone.utc), spec.cursor))
    page, offset = p.start_page, 0
    if p.type == "page_number":
        put(p.params_in, p.page_param, page)
    if p.type in ("page_number", "offset", "link_header", "next_token") and p.page_size_param:
        put(p.params_in, p.page_size_param, p.page_size)
    if p.type == "offset":
        put(p.params_in, p.offset_param, 0)
        if p.offset_end_param:
            put(p.params_in, p.offset_end_param, p.page_size)
    for _ in range(p.max_pages):
        resp = await fetcher.request(req.method, url, params, body)
        try:
            data = xml_to_dict(resp.text) if req.response_format == "xml" else resp.json()
        except (ValueError, MappingError) as e:
            raise FetchError(f"response body is not valid {req.response_format.upper()}: {e}") from e
        records = get_path(data, spec.records)
        if not spec.records and isinstance(records, dict):
            records = find_records(records)  # `records` left out: use the response's list of objects
        elif spec.records and isinstance(records, dict):
            records = [records]              # the endpoint returns one object (e.g. an IP lookup): one record
        if records is None:
            records = []
        if not isinstance(records, list):
            raise FetchError(f"'records: {spec.records}' did not resolve to a list")
        yield records
        if p.type == "none":
            return
        if p.has_more_path and not get_path(data, p.has_more_path):
            return
        if p.type in ("next_url", "next_token") and not token_path:
            token_path = find_next(data, "url" if p.type == "next_url" else "token")
            if token_path:  # the config did not say where the next page is: found it in the response
                fetcher.metrics.notes.append(f"next page: found the {'link' if p.type == 'next_url' else 'token'} "
                                             f"at `{token_path}` (add `token_path: {token_path}` to pin it)")
        if p.type in ("link_header", "next_url"):
            nxt = resp.links.get("next", {}).get("url") if p.type == "link_header" else \
                (get_path(data, token_path) if token_path else None)
            if not nxt:
                return
            url, params = urljoin(str(resp.url), nxt), {}
        elif p.type == "next_token":
            token = get_path(data, token_path) if token_path else None
            if not token or not records:  # some APIs keep handing out a token on an empty last page
                return
            if not token_param:  # not named in the config: next_cursor -> cursor, nextPageToken -> pageToken
                leaf = re.split(r"[.\[']", token_path.rstrip("]'"))[-1]
                token_param = re.sub(r"^next_?", "", leaf) or leaf
                token_param = token_param[0].lower() + token_param[1:]
                fetcher.metrics.notes.append(f"next page: sending the token as `{token_param}` "
                                             f"(add `token_param: {token_param}` to pin it)")
            put(p.token_in, token_param, token)
        elif p.type == "page_number":
            if len(records) < p.page_size or not records:
                return
            page += 1
            put(p.params_in, p.page_param, page)
        elif p.type == "offset":
            offset += len(records)
            total = get_path(data, p.total_path) if p.total_path else None
            if not records or (total is not None and offset >= int(total)) or \
                    (total is None and len(records) < p.page_size):
                return
            put(p.params_in, p.offset_param, offset)
            if p.offset_end_param:
                put(p.params_in, p.offset_end_param, offset + p.page_size)
    fetcher.metrics.notes.append(f"stopped at max_pages={p.max_pages}; the rest is fetched next run")
