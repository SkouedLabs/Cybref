"""NIST NVD bulk feeds (CVE JSON 2.0 per year + CPE dictionary)."""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import logging
import lzma
import tarfile
from contextlib import ExitStack
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from ..engine import Context, gzip_open_write
from ..http import get_text

logger = logging.getLogger("cybref.nvd")

_CVE_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
_CPE_BUNDLE = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"


async def cve_feeds(ctx: Context) -> None:
    """Every yearly feed + recent + modified, kept as the original .json.gz.

    NVD publishes a .meta file (sha256 of the JSON) next to each feed: a feed is
    only re-downloaded when its sha256 changed, and the download is verified against it.
    """
    first_year = int(ctx.options.get("first_year", 2002))
    names = [f"nvdcve-2.0-{y}" for y in range(first_year, date.today().year + 1)]
    names += ["nvdcve-2.0-recent", "nvdcve-2.0-modified"]
    known: dict = ctx.state.setdefault("sha256", {})
    folder = ctx.options["dir"].rstrip("/")
    sem = asyncio.Semaphore(3)

    async def one(name: str) -> None:
        async with sem:
            out = f"{folder}/{name}.json.gz"
            sha = None
            try:
                meta = await get_text(ctx.client, f"{_CVE_BASE}/{name}.meta")
                sha = _meta_sha256(meta)
            except Exception as exc:  # noqa: BLE001 - meta is an optimisation only
                logger.warning("[nvd] %s.meta unavailable: %s", name, exc)
            if sha and not ctx.force and known.get(name) == sha and ctx.published(out).is_file():
                return
            target = ctx.work / f"{name}.json.gz"
            await ctx.download(f"{_CVE_BASE}/{name}.json.gz", target)
            if sha:
                actual = await asyncio.to_thread(_gunzip_sha256, target)
                if actual != sha:
                    # NVD regenerates feeds continuously: meta and feed may have raced.
                    sha = _meta_sha256(await get_text(ctx.client, f"{_CVE_BASE}/{name}.meta"))
                    if actual != sha:
                        await ctx.download(f"{_CVE_BASE}/{name}.json.gz", target)
                        if await asyncio.to_thread(_gunzip_sha256, target) != sha:
                            raise ValueError("sha256 mismatch with .meta (corrupted download?)")
                known[name] = sha
            # Staged only once complete and verified (a failed year leaves nothing behind).
            target.replace(ctx.path(out))
            logger.info("[nvd] %s downloaded", out)

    results = await asyncio.gather(*(one(n) for n in names), return_exceptions=True)
    failed = [f"{n}: {r}" for n, r in zip(names, results) if isinstance(r, BaseException)]
    if len(failed) == len(names):
        raise RuntimeError(f"every NVD feed failed, first: {failed[0]}")
    # One flaky year must not block the others: publish what worked, report the rest.
    ctx.errors.extend(failed)


def _meta_sha256(meta: str) -> str | None:
    for line in meta.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "sha256":
            return value.strip().lower()
    return None


def _gunzip_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with gzip.open(path, "rb") as fh:
        while chunk := fh.read(8 << 20):
            h.update(chunk)
    return h.hexdigest()


async def cpe_dictionary(ctx: Context) -> None:
    """CPE 2.0 bundle (tar of JSON chunks) re-split by vendor initial: <dir>/<a-z|0-9|other>.json.gz,
    each {"products": [...]}.

    One merged file would exceed GitHub's 100 MB limit (1.8M+ products and growing); a split by
    vendor is stable over time and lets consumers load only what they look up.
    Streams chunk by chunk so memory stays bounded.
    """
    bundle = await ctx.download(_CPE_BUNDLE, cache=True)
    subdir = ctx.options["dir"].rstrip("/")
    count = await asyncio.to_thread(_split_cpe, bundle, ctx.work / "cpe", ctx.stage / subdir)
    if count < 100_000:
        raise ValueError(f"only {count} CPE products found")
    logger.info("[nvd] CPE dictionary: %d products", count)


def _bucket(product: dict) -> str:
    name = product.get("cpe", {}).get("cpeName", "")
    parts = name.split(":")
    initial = parts[3][:1].lower() if len(parts) > 3 else ""
    if initial.isascii() and initial.isalpha():
        return initial
    return "0-9" if initial.isdigit() else "other"


def _split_cpe(bundle: Path, workdir: Path, target_dir: Path) -> int:
    with tarfile.open(bundle, "r:gz") as tar:
        tar.extractall(workdir, filter="data")
    chunks = sorted(workdir.rglob("*.json"))
    count = 0
    with ExitStack() as stack:
        writers: dict[str, tuple] = {}

        def writer(bucket: str):
            if bucket not in writers:
                fh = stack.enter_context(gzip_open_write(target_dir / f"{bucket}.json.gz"))
                fh.write(b'{"products":[')
                stack.callback(fh.write, b"]}")
                writers[bucket] = (fh, [0])
            return writers[bucket]

        for chunk in chunks:
            for product in json.loads(chunk.read_bytes()).get("products", []):
                fh, n = writer(_bucket(product))
                fh.write((b"," if n[0] else b"") + json.dumps(product, separators=(",", ":")).encode())
                n[0] += 1
                count += 1
            chunk.unlink()
    return count


_RECENT_FEED = f"{_CVE_BASE}/nvdcve-2.0-recent.json.gz"


async def cve_recent(ctx: Context) -> None:
    """CVEs published over a rolling window of the last `days` days.

    Built from NVD's `recent` feed, which carries roughly the last 8 days of newly published
    CVEs and is regenerated by NVD every two hours - polling it more often than that only
    re-reads the same bytes. The feed is small (~1.4 MB gzipped), so it is re-read in full on
    every run and the window recomputed from scratch rather than merged into the previous
    output: days roll off on their own and nothing can drift.

    Deliberately not conditional on the feed's sha256: the window moves with the clock, so an
    unchanged feed can still mean a changed output. The engine compares the result byte for
    byte anyway and republishes nothing when it did not move.
    """
    days = int(ctx.options.get("days", 7))
    min_cves = int(ctx.options.get("min_cves", 300))

    raw = await ctx.download(_RECENT_FEED)
    feed = await asyncio.to_thread(lambda: json.loads(gzip.open(raw, "rb").read()))
    entries = feed.get("vulnerabilities") or []
    if not entries:
        raise ValueError("the recent feed carries no vulnerability")

    # Day-aligned on purpose: a cutoff of "now minus 7 days" would move every second, so the
    # file's bytes would differ at every run and be republished even when NVD added nothing.
    # Whole UTC days also match how a 7-day history is actually read.
    first_day = datetime.now(timezone.utc).date() - timedelta(days=days - 1)
    cutoff = datetime.combine(first_day, datetime.min.time(), tzinfo=timezone.utc)
    kept = []
    oldest = None
    for entry in entries:
        published = _nvd_published(entry)
        if published is None:
            continue
        oldest = published if oldest is None else min(oldest, published)
        if published >= cutoff:
            kept.append(entry)
    if len(kept) < min_cves:
        raise ValueError(f"only {len(kept)} CVEs published in the last {days} days "
                         f"(min {min_cves}) - is the feed stale?")
    # The feed is NVD's to size: if it ever stops reaching back far enough, say so instead
    # of quietly publishing a shorter window.
    if oldest is not None and oldest > cutoff:
        ctx.errors.append(f"the recent feed only reaches back to {oldest:%Y-%m-%d %H:%M} UTC, "
                          f"short of the {days}-day window")

    kept.sort(key=lambda e: e["cve"]["id"])  # sorted: identical content -> identical bytes
    # The envelope carries nothing that moves on its own: no run timestamp, and the feed's own
    # timestamp goes to the run state instead. The file then changes only when the CVEs do,
    # and the engine skips the republish the rest of the time.
    ctx.write_json(ctx.source.output, {
        "format": feed.get("format", "NVD_CVE"),
        "version": feed.get("version", "2.0"),
        "source": _RECENT_FEED,
        "windowDays": days,
        "windowStart": f"{first_day:%Y-%m-%d}",
        "cveCount": len(kept),
        "vulnerabilities": kept,
    })
    ctx.state["feed_timestamp"] = feed.get("timestamp")
    ctx.state["window_start"] = f"{first_day:%Y-%m-%d}"
    logger.info("[nvd] %d CVEs published since %s (feed of %d, generated %s)",
                len(kept), first_day, len(entries), feed.get("timestamp"))


def _nvd_published(entry: dict) -> datetime | None:
    """`published` is naive ISO-8601 in UTC, e.g. 2026-10-27T15:15:00.000."""
    raw = (entry.get("cve") or {}).get("published")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


_FKIE_RELEASE = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"


async def fkie_feeds(ctx: Context) -> None:
    """Fraunhofer FKIE's rebuild of the NVD CVE corpus, one feed per year.

    The NVD 2.0 bulk feeds NIST publishes lag behind its own API and need a key to be
    read incrementally; FKIE regenerates the whole corpus daily from the API and ships
    it as `CVE-<year>.json.xz` release assets with a `.meta` carrying the sha256 of the
    decompressed JSON. The .xz is a quarter the size of the equivalent .gz, so the
    transfer is cheap, and an unchanged year is skipped on its sha256 like the NVD feeds.
    Republished as .json.gz to keep one compression format across the catalog.
    """
    first_year = int(ctx.options.get("first_year", 1999))
    folder = ctx.options["dir"].rstrip("/")
    stem = ctx.options.get("stem", ctx.source.id)
    known: dict = ctx.state.setdefault("sha256", {})
    years = list(range(first_year, date.today().year + 1))
    sem = asyncio.Semaphore(3)

    async def one(year: int) -> None:
        name = f"CVE-{year}"
        out = f"{folder}/{stem}_{year}.json.gz"
        async with sem:
            sha = None
            try:
                sha = _meta_sha256(await get_text(ctx.client, f"{_FKIE_RELEASE}/{name}.meta"))
            except Exception as exc:  # noqa: BLE001 - meta is an optimisation only
                logger.warning("[fkie] %s.meta unavailable: %s", name, exc)
            if sha and not ctx.force and known.get(name) == sha and ctx.published(out).is_file():
                return
            archive = ctx.work / f"{name}.json.xz"
            await ctx.download(f"{_FKIE_RELEASE}/{name}.json.xz", archive)
            actual = await asyncio.to_thread(_unxz_to_gzip, archive, ctx.path(out))
            if sha and actual != sha:
                raise ValueError(f"{name}: sha256 mismatch with .meta (corrupted download?)")
            if sha:
                known[name] = sha

    results = await asyncio.gather(*(one(y) for y in years), return_exceptions=True)
    failed = [f"{y}: {r}" for y, r in zip(years, results) if isinstance(r, Exception)]
    if len(failed) == len(years):
        raise RuntimeError("; ".join(failed)[:400])
    ctx.errors.extend(failed)


def _unxz_to_gzip(archive: Path, target: Path) -> str:
    """Decompress the .xz straight into a deterministic .gz, hashing the JSON on the way."""
    h = hashlib.sha256()
    with lzma.open(archive, "rb") as fin, gzip_open_write(target) as fout:
        while chunk := fin.read(8 << 20):
            h.update(chunk)
            fout.write(chunk)
    return h.hexdigest()
