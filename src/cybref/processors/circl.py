"""CIRCL Vulnerability-Lookup: paginated JSON API.

https://vulnerability.circl.lu/api/ answers `{"metadata": {count, page, per_page},
"data": [...]}` on every collection endpoint, with `per_page` capped at 1000. The dumps
published at /dumps/ cover the same ground but are regenerated irregularly (and several
are empty), so the API is the only current source.
"""

from __future__ import annotations

import json
import logging

from ..engine import Context
from ..http import get_text

logger = logging.getLogger("cybref.circl")

BASE = "https://vulnerability.circl.lu/api"
PER_PAGE = 1000  # the API caps it there
MAX_PAGES = 4000
SEP = chr(31)  # unit separator: joins the fields of a composite identity


def _ident(item: dict, key: tuple[str, ...]) -> str:
    """The identity of a record: one field, or several joined.

    A single field is not always enough. /vex/ keys its rows on the vulnerability, and
    several publishers issue a VEX for the same CVE, so `id` alone would discard two
    records out of five as duplicates - `meta_source` + `id` is what identifies one.
    """
    return SEP.join(str(item.get(k) or "") for k in key)


async def _pages(ctx: Context, endpoint: str, params: dict, key: tuple[str, ...]):
    """Yield every item of a collection endpoint, deduplicated on *key*.

    `metadata.count` drifts while the crawl runs (sightings land continuously), so it is
    used as a progress hint only: the walk stops on a short or empty page.
    """
    per_page = int(ctx.options.get("per_page", PER_PAGE))
    seen: set[str] = set()
    page = 1
    total: int | None = None
    while page <= MAX_PAGES:
        body = await get_text(ctx.client, f"{BASE}/{endpoint}",
                              params={**params, "page": page, "per_page": per_page})
        payload = json.loads(body)
        if isinstance(payload, list):  # a few endpoints answer a bare array
            batch, meta = payload, {}
        else:
            batch, meta = payload.get("data") or [], payload.get("metadata") or {}
        # /bundle/ and /comment/ silently cap per_page at 100 and answer with the value
        # they actually applied, so the stride has to come from the response, not the ask.
        stride = int(meta.get("per_page") or per_page)
        if total is None:
            total = meta.get("count")
            logger.info("[%s] %s: %s record(s) announced, %d per page",
                        ctx.source.id, endpoint, total, stride)
        for item in batch:
            ident = _ident(item, key)
            if ident.strip(SEP) and ident in seen:
                continue
            if ident:
                seen.add(ident)
            yield item
        if len(batch) < stride:
            break
        page += 1
    else:
        raise RuntimeError(f"{endpoint}: pagination did not converge after {MAX_PAGES} pages")

    if total and len(seen) < total * 0.9:
        raise ValueError(f"{endpoint}: collected {len(seen)} of {total} announced records")


async def collection(ctx: Context) -> None:
    """One Vulnerability-Lookup collection endpoint as a sorted JSON array.

    options: endpoint (required), key (dedup/sort field, or a list of fields that
             together identify a record; default "uuid"), params (extra query string),
             min_records, per_page.
    """
    endpoint = ctx.options["endpoint"].strip("/")
    raw_key = ctx.options.get("key", "uuid")
    key = tuple(raw_key) if isinstance(raw_key, list) else (raw_key,)
    params = dict(ctx.options.get("params") or {})
    minimum = int(ctx.options.get("min_records", 1))

    items = [item async for item in _pages(ctx, endpoint, params, key)]
    if len(items) < minimum:
        raise ValueError(f"{endpoint}: {len(items)} records (min {minimum})")
    # Sorted so identical content yields identical bytes: the engine republishes on sha256.
    items.sort(key=lambda i: _ident(i, key))
    ctx.write_json(ctx.source.output, items)
    logger.info("[%s] %d record(s)", ctx.source.id, len(items))
