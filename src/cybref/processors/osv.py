"""OSV.dev per-ecosystem advisory archives."""

from __future__ import annotations

import asyncio
import json
import zipfile
from pathlib import Path

from ..engine import Context, ShardWriter, gzip_open_write


async def advisories_zip(ctx: Context) -> None:
    """OSV `all.zip`: one JSON file per advisory, merged into a single gzipped array.

    Ecosystems whose merged array would exceed the publication limit (npm, Ubuntu...)
    declare `shard: true` and get `<stem>_01.json.gz`, `_02`... instead, cut on size.
    """
    archive = await ctx.download(ctx.source.resolved_urls()[0], cache=True)
    minimum = ctx.options.get("min_advisories", 1000)
    if ctx.options.get("shard"):
        count, shards = await asyncio.to_thread(_merge_sharded, ctx, archive)
        ctx.state["shards"] = shards
    else:
        count = await asyncio.to_thread(_merge_zip, archive, ctx.path(ctx.source.output))
    if count < minimum:
        raise ValueError(f"only {count} advisories merged (min {minimum})")


def _records(zf: zipfile.ZipFile):
    """Every advisory in the archive, in a stable order, as compact JSON bytes."""
    for name in sorted(n for n in zf.namelist() if n.endswith(".json")):
        try:
            doc = json.loads(zf.read(name))
        except ValueError:
            continue
        yield json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode()


def _merge_zip(archive: Path, target: Path) -> int:
    count = 0
    with zipfile.ZipFile(archive) as zf, gzip_open_write(target) as out:
        out.write(b"[")
        for row in _records(zf):
            out.write((b"," if count else b"") + row)
            count += 1
        out.write(b"]")
    return count


def _merge_sharded(ctx: Context, archive: Path) -> tuple[int, int]:
    folder = ctx.options["dir"].rstrip("/")
    stem = ctx.options.get("stem", ctx.source.id)
    count = 0
    with zipfile.ZipFile(archive) as zf:
        with ShardWriter(lambda i: ctx.path(f"{folder}/{stem}_{i:02d}.json.gz")) as out:
            for row in _records(zf):
                out.write(row)
                count += 1
            shards = out.close()
    return count, shards
