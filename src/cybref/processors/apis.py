"""Paginated JSON APIs."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import ExitStack
from datetime import date
from pathlib import Path

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


def _euvd_id_year(eid: str) -> str:
    """EUVD-2024-12345 -> "2024". The shard key, as NVD keys its feeds on the CVE year:
    an entry never changes shard, and a known id tells you which file to open."""
    parts = eid.split("-")
    return parts[1] if len(parts) > 2 and parts[1].isdigit() and len(parts[1]) == 4 else "other"


async def euvd_full(ctx: Context) -> None:
    """ENISA EUVD, the whole database, as one gzipped JSON array per year (NVD feed layout).

    One `size=100` page is the only way out of the API (no bulk export), so the crawl is
    driven by publication year: each year paginates independently, which keeps the offsets
    shallow and stops entries published mid-crawl from shifting the pages of past years.
    The shards themselves are keyed on the year inside the EUVD id, which is not the same
    year for ~20% of the base (a vulnerability published in January of the following year),
    so entries are spilled to one scratch file per id year and only then sorted and written.
    One merged file is not an option: 400k+ entries weigh ~140 MB gzipped, past GitHub's limit.
    """
    folder = ctx.options["dir"].rstrip("/")
    stem = ctx.options.get("stem", ctx.source.id)
    first_year = int(ctx.options.get("first_year", 1999))
    min_entries = int(ctx.options.get("min_entries", 300_000))
    pace = float(ctx.options.get("pace", 0.3))  # ~4200 pages: stay under the rate limiter
    years = range(first_year, date.today().year + 2)  # +1: entries dated ahead of today

    seen: set[str] = set()
    spill = ctx.work / "by-id-year"
    spill.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        handles: dict[str, object] = {}
        for year in years:
            fresh = 0
            params = {"fromDate": f"{year}-01-01", "toDate": f"{year}-12-31"}
            async for item in _euvd_pages(ctx, params, pace):
                eid = item.get("id")
                if not eid or eid in seen:
                    continue
                seen.add(eid)
                key = _euvd_id_year(eid)
                if key not in handles:
                    handles[key] = stack.enter_context(
                        (spill / f"{key}.jsonl").open("w", encoding="utf-8", newline="\n"))
                row = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                handles[key].write(row + "\n")
                fresh += 1
            if fresh:
                logger.info("[euvd] published in %d: %d entries (running total %d)",
                            year, fresh, len(seen))

    if len(seen) < min_entries:
        raise ValueError(f"EUVD: only {len(seen)} entries collected (expected >= {min_entries})")
    shards = await asyncio.to_thread(_euvd_write_shards, ctx, spill, folder, stem)
    logger.info("[euvd] %d entries in %d shards", len(seen), shards)


def _euvd_write_shards(ctx: Context, spill: Path, folder: str, stem: str) -> int:
    """One sorted JSON array per id year. Sorted so identical content yields identical bytes:
    the engine republishes a file only when its sha256 moved."""
    count = 0
    for scratch in sorted(spill.glob("*.jsonl")):
        # Iterated line by line, never str.splitlines(): descriptions keep raw U+2028/U+2029
        # (ensure_ascii=False does not escape them) and splitlines() would cut a record in two.
        with scratch.open(encoding="utf-8", newline="\n") as fh:
            rows = sorted((json.loads(line)["id"], line.rstrip("\n"))
                          for line in fh if line.strip())
        scratch.unlink()
        if not rows:
            continue
        with gzip_open_write(ctx.path(f"{folder}/{stem}_{scratch.stem}.json.gz")) as shard:
            shard.write(b"[")
            for i, (_, line) in enumerate(rows):
                shard.write((b"," if i else b"") + line.encode("utf-8"))
            shard.write(b"]")
        count += 1
    return count


_ATLAS_DIST = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist"


async def mitre_atlas(ctx: Context) -> None:
    """MITRE ATLAS: the *-latest.yaml files are git symlinks (served as a one-line path),
    so resolve the current release from dist/manifest.yaml."""
    manifest = yaml.safe_load(await get_text(ctx.client, f"{_ATLAS_DIST}/manifest.yaml"))
    releases = sorted(manifest, key=lambda r: str(r.get("release-date", "")), reverse=True)
    path = releases[0]["versions"][-1]["path"]
    await ctx.download(f"{_ATLAS_DIST}/{path}", ctx.path(ctx.source.output), cache=True)
