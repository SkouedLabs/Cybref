"""CSAF / VEX bulk archives published by vendors."""

from __future__ import annotations

import asyncio
import json
import logging
import tarfile
from contextlib import ExitStack
from pathlib import Path

from ..engine import Context, ShardWriter, zstd_open
from ..http import get_text

logger = logging.getLogger("cybref.csaf")

_RH_VEX = "https://security.access.redhat.com/data/csaf/v2/vex"


async def redhat_vex(ctx: Context) -> None:
    """Red Hat's CSAF VEX corpus: one statement per CVE, ~75k documents.

    Red Hat publishes a dated `csaf_vex_<date>.tar.zst` plus an `archive_latest.txt`
    naming the current one, so the pointer is resolved first rather than guessing a
    date. The archive holds `<year>/cve-<id>.json`; the merged corpus is far past the
    publication limit, so it is written as one gzipped JSON array per year.
    """
    folder = ctx.options["dir"].rstrip("/")
    stem = ctx.options.get("stem", ctx.source.id)
    minimum = int(ctx.options.get("min_documents", 50_000))

    latest = (await get_text(ctx.client, f"{_RH_VEX}/archive_latest.txt")).strip()
    if not latest.endswith(".tar.zst"):
        raise ValueError(f"unexpected archive_latest.txt content: {latest[:120]!r}")
    if not ctx.force and ctx.state.get("archive") == latest and _has_output(ctx, folder):
        logger.info("[%s] %s already published", ctx.source.id, latest)
        return

    logger.info("[%s] current archive: %s", ctx.source.id, latest)
    archive = await ctx.download(f"{_RH_VEX}/{latest}", ctx.work / latest)
    total, years = await asyncio.to_thread(_split_by_year, archive, ctx, folder, stem)
    if total < minimum:
        raise ValueError(f"only {total} VEX documents extracted (min {minimum})")
    ctx.state["archive"] = latest
    logger.info("[%s] %d document(s) in %d yearly shard(s)", ctx.source.id, total, years)


def _has_output(ctx: Context, folder: str) -> bool:
    return any(ctx.published(folder).glob("*.json.gz")) if ctx.published(folder).is_dir() else False


def _split_by_year(archive: Path, ctx: Context, folder: str, stem: str) -> tuple[int, int]:
    """Stream the tar once, writing each document into its year's shard.

    Streaming matters: the archive expands to several GB and tarfile cannot seek inside a
    zstd stream, so a second pass would mean decompressing the whole thing again. Each
    year keeps its own open writer, which rolls over if one year outgrows the file limit.
    """
    total = 0
    with ExitStack() as stack:
        writers: dict[str, ShardWriter] = {}
        reader = stack.enter_context(zstd_open(archive))
        tar = stack.enter_context(tarfile.open(fileobj=reader, mode="r|"))
        for member in tar:
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            parts = member.name.strip("./").split("/")
            year = next((p for p in parts if len(p) == 4 and p.isdigit()), "other")
            fh = tar.extractfile(member)
            if fh is None:
                continue
            try:
                doc = json.loads(fh.read())
            except ValueError:
                continue
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
