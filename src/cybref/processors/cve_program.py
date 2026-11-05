"""The CVE Program's own record list (cvelistV5)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import zipfile
from contextlib import ExitStack
from pathlib import Path

from ..engine import Context, ShardWriter
from ..http import get_text

logger = logging.getLogger("cybref.cve_program")

_RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
_CVE_ID = re.compile(r"CVE-(\d{4})-\d+", re.I)


async def cvelist_v5(ctx: Context) -> None:
    """Every published CVE record in CVE JSON 5.1, as one gzipped array per year.

    This is the upstream the NVD and everyone else derives from: the CNA containers,
    before any enrichment. The project publishes a full snapshot every midnight and an
    hourly delta as GitHub release assets, with the release tag carrying the hour, so
    the current asset is resolved from the releases API rather than built from a date.
    The snapshot is rebuilt whole each run: merging the delta would mean rewriting the
    shards already published, for a file the engine republishes on content anyway.
    """
    folder = ctx.options["dir"].rstrip("/")
    stem = ctx.options.get("stem", ctx.source.id)
    minimum = int(ctx.options.get("min_records", 200_000))

    headers = {"Accept": "application/vnd.github+json"}
    release = json.loads(await get_text(ctx.client, _RELEASES, headers=headers))
    tag = release.get("tag_name", "?")
    assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
    name = next((n for n in sorted(assets) if "all_CVEs" in n), None)
    if not name:
        raise ValueError(f"release {tag} has no full snapshot asset: {sorted(assets)[:5]}")
    if not ctx.force and ctx.state.get("asset") == name and _has_output(ctx, folder):
        logger.info("[%s] %s already published", ctx.source.id, name)
        return

    logger.info("[%s] release %s, asset %s", ctx.source.id, tag, name)
    archive = await ctx.download(assets[name], ctx.work / "cvelist.zip")
    total, shards = await asyncio.to_thread(_split_by_year, archive, ctx, folder, stem)
    if total < minimum:
        raise ValueError(f"only {total} CVE records extracted (min {minimum})")
    ctx.state["asset"] = name
    logger.info("[%s] %d record(s) in %d yearly shard(s)", ctx.source.id, total, shards)


def _has_output(ctx: Context, folder: str) -> bool:
    return any(ctx.published(folder).glob("*.json.gz")) if ctx.published(folder).is_dir() else False


def _open_payload(archive: Path, stack: ExitStack) -> zipfile.ZipFile:
    """The snapshot asset is a zip wrapping a zip (hence its `.zip.zip` name)."""
    outer = stack.enter_context(zipfile.ZipFile(archive))
    inner = [n for n in outer.namelist() if n.lower().endswith(".zip")]
    if len(inner) == 1:
        extracted = archive.with_name("inner.zip")
        with outer.open(inner[0]) as fin, extracted.open("wb") as fout:
            while chunk := fin.read(8 << 20):
                fout.write(chunk)
        return stack.enter_context(zipfile.ZipFile(extracted))
    return outer


def _split_by_year(archive: Path, ctx: Context, folder: str, stem: str) -> tuple[int, int]:
    """One gzipped array per CVE year, each rolling over if it outgrows the file limit.

    Members are walked in sorted path order, which groups and orders records the same way
    on every run, so an unchanged year yields byte-identical shards.
    """
    total = 0
    with ExitStack() as stack:
        zf = _open_payload(archive, stack)
        writers: dict[str, ShardWriter] = {}
        for name in sorted(zf.namelist()):
            if not name.endswith(".json"):
                continue
            match = _CVE_ID.search(name.rsplit("/", 1)[-1])
            if not match:
                continue  # deltaLog.json, release notes, metadata...
            try:
                doc = json.loads(zf.read(name))
            except ValueError:
                continue
            year = match.group(1)
            if year not in writers:
                writers[year] = stack.enter_context(ShardWriter(_shard_name(ctx, folder, stem, year)))
            writers[year].write(json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode())
            total += 1
        shards = sum(len(w.shards) for w in writers.values())
    return total, shards


def _shard_name(ctx: Context, folder: str, stem: str, year: str):
    """`<stem>_<year>.json.gz`, with a numbered suffix only if that year overflows."""
    def name(index: int) -> Path:
        suffix = "" if index == 1 else f"_{index:02d}"
        return ctx.path(f"{folder}/{stem}_{year}{suffix}.json.gz")
    return name
