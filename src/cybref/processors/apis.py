"""Paginated JSON APIs."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import date

import httpx
import yaml

from ..engine import Context, gzip_open_write
from ..http import get_text

logger = logging.getLogger("cybref.apis")

_EUVD_SEARCH = "https://euvdservices.enisa.europa.eu/api/search"


async def euvd_exploited(ctx: Context) -> None:
    """ENISA EUVD: every vulnerability flagged as exploited (API pages are capped at 100)."""
    items: dict[str, dict] = {}
    total = None
    page = 0
    while total is None or len(items) < total:
        data = json.loads(await get_text(
            ctx.client, _EUVD_SEARCH, params={"exploited": "true", "size": 100, "page": page},
        ))
        batch = data.get("items") or []
        total = data.get("total", 0)
        if not batch:
            break
        items.update((i["id"], i) for i in batch if i.get("id"))
        page += 1
        if page > 500:
            raise RuntimeError("EUVD pagination did not converge")
    if total and len(items) < total * 0.95:
        raise ValueError(f"EUVD: got {len(items)} of {total} exploited entries")
    ctx.write_json(ctx.source.output, [items[k] for k in sorted(items)], indent=1)


_EUVD_PAGE = 100  # the API caps `size` at 100


async def _euvd_page(ctx: Context, params: dict, attempts: int = 6) -> dict:
    """One page. The API answers 403 (not 429) when it decides a client reads too fast,
    and get_text() does not retry that, so back off here."""
    for attempt in range(1, attempts + 1):
        try:
            return json.loads(await get_text(ctx.client, _EUVD_SEARCH, params=params))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 403 or attempt == attempts:
                raise
            wait = min(15 * 2 ** (attempt - 1), 300)
            logger.warning("[euvd] HTTP 403 on %s, slowing down %.0fs (%d/%d)",
                           params, wait, attempt, attempts - 1)
            await asyncio.sleep(wait)
    raise RuntimeError("unreachable")


async def _euvd_pages(ctx: Context, params: dict, pace: float):
    """Yield every item matching *params*, page by page."""
    total = None
    page = 0
    while total is None or page * _EUVD_PAGE < total:
        data = await _euvd_page(ctx, {**params, "size": _EUVD_PAGE, "page": page})
        if total is None:
            total = data.get("total", 0)
            if not total:
                return
        items = data.get("items") or []
        if not items:
            break
        for item in items:
            yield item
        page += 1
        if page > 2000:
            raise RuntimeError(f"EUVD pagination did not converge for {params}")
        if pace:
            await asyncio.sleep(pace)


async def euvd_full(ctx: Context) -> None:
    """ENISA EUVD, the whole database.

    One `size=100` page is the only way out of the API (no bulk export), so the crawl is
    split per publication year: each year paginates independently, which keeps the offsets
    shallow and stops entries published mid-crawl from shifting the pages of past years.
    Published as one gzipped NDJSON stream plus one JSON array per year - a single JSON
    array of 400k+ entries would blow past GitHub's 100 MB limit and is unusable anyway.
    """
    folder = ctx.options["dir"].rstrip("/")
    stem = ctx.options.get("stem", ctx.source.id)
    first_year = int(ctx.options.get("first_year", 1988))
    min_entries = int(ctx.options.get("min_entries", 300_000))
    pace = float(ctx.options.get("pace", 0.3))  # ~4200 pages: stay under the rate limiter
    years = range(first_year, date.today().year + 2)  # +1: entries dated ahead of today

    seen: set[str] = set()
    shards = 0
    with gzip_open_write(ctx.path(f"{folder}/{stem}.jsonl.gz")) as stream:
        for year in years:
            rows: list[tuple[str, str]] = []
            params = {"fromDate": f"{year}-01-01", "toDate": f"{year}-12-31"}
            pages = _euvd_pages(ctx, params, pace)
            async for item in pages:
                eid = item.get("id")
                if not eid or eid in seen:
                    continue
                seen.add(eid)
                rows.append((eid, json.dumps(item, ensure_ascii=False, separators=(",", ":"))))
            if not rows:
                continue
            rows.sort()
            # Shard = the year an entry was first met, scanning years upwards: shards stay
            # disjoint and their union is the full stream, whatever the API's date filter does.
            with gzip_open_write(ctx.path(f"{folder}/{stem}_{year}.json.gz")) as shard:
                shard.write(b"[")
                for i, (_, line) in enumerate(rows):
                    shard.write((b"," if i else b"") + line.encode("utf-8"))
                shard.write(b"]")
            for _, line in rows:
                stream.write(line.encode("utf-8") + b"\n")
            shards += 1
            logger.info("[euvd] %d: %d entries (running total %d)", year, len(rows), len(seen))

    if len(seen) < min_entries:
        raise ValueError(f"EUVD: only {len(seen)} entries collected (expected >= {min_entries})")
    logger.info("[euvd] %d entries in %d yearly shards", len(seen), shards)


_ATLAS_DIST = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist"


async def mitre_atlas(ctx: Context) -> None:
    """MITRE ATLAS: the *-latest.yaml files are git symlinks (served as a one-line path),
    so resolve the current release from dist/manifest.yaml."""
    manifest = yaml.safe_load(await get_text(ctx.client, f"{_ATLAS_DIST}/manifest.yaml"))
    releases = sorted(manifest, key=lambda r: str(r.get("release-date", "")), reverse=True)
    path = releases[0]["versions"][-1]["path"]
    await ctx.download(f"{_ATLAS_DIST}/{path}", ctx.path(ctx.source.output), cache=True)
