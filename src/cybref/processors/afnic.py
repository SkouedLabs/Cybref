"""AFNIC open data: the full registered-domain list, and the daily creation feed."""

from __future__ import annotations

import asyncio
import logging
import zipfile
from contextlib import ExitStack
from datetime import date, timedelta
from pathlib import Path

import httpx

from ..engine import Context, gzip_open_write
from ..http import NotModified, get_text

logger = logging.getLogger("cybref.afnic")


async def domains(ctx: Context) -> None:
    """The monthly .fr archive, re-split by domain initial: <dir>/<a-z|0-9|other>.csv.gz.

    The CSV is 713 MB raw and ~123 MB gzipped as one file, past GitHub's 100 MB limit, so it
    cannot be published whole. Parquet does not rescue it either: 10M unique domain names are
    near-incompressible, and even zstd + delta encoding only reaches ~95 MB, which leaves no
    room for a zone that grows every month. The archive is sorted by domain name, so a split
    by initial is stable month to month and lets consumers load only the bucket they look up.
    Streamed straight out of the zip: the full CSV never lands on disk.
    """
    archive = await _download(ctx)
    subdir = ctx.options["dir"].rstrip("/")
    minimum = ctx.options.get("min_domains", 3_000_000)
    count, buckets = await asyncio.to_thread(_split, archive, ctx.stage / subdir)
    if count < minimum:
        raise ValueError(f"only {count} domains (min {minimum})")
    logger.info("[afnic] %d domains across %d buckets", count, buckets)


async def _download(ctx: Context) -> Path:
    """AFNIC publishes a month's archive during the following month: try each candidate."""
    urls = ctx.source.resolved_urls()
    last_exc: Exception | None = None
    for url in urls:
        try:
            return await ctx.download(url, cache=len(urls) == 1)
        except NotModified:
            raise
        except Exception as exc:  # noqa: BLE001 - fall back to the other month
            last_exc = exc
    assert last_exc is not None
    raise last_exc


def _bucket(line: bytes) -> str:
    """First byte of the domain name; IDN domains start with a multi-byte char -> "other"."""
    initial = line[:1].lower()
    if b"a" <= initial <= b"z":
        return initial.decode()
    return "0-9" if initial.isdigit() else "other"


def _split(archive: Path, target_dir: Path) -> tuple[int, int]:
    with zipfile.ZipFile(archive) as zf:
        members = [n for n in zf.namelist() if n.lower().endswith(".csv")]
        if len(members) != 1:
            raise ValueError(f"expected exactly one CSV in the archive, found {members or 'none'}")
        count = 0
        writers: dict[str, object] = {}
        with zf.open(members[0]) as raw, ExitStack() as stack:
            header = raw.readline()
            if b";" not in header:
                raise ValueError(f"unexpected header: {header[:120]!r}")
            for line in raw:
                if not line.strip():
                    continue
                bucket = _bucket(line)
                if bucket not in writers:
                    fh = stack.enter_context(gzip_open_write(target_dir / f"{bucket}.csv.gz"))
                    fh.write(header)
                    writers[bucket] = fh
                writers[bucket].write(line)
                count += 1
    return count, len(writers)


_CREA_URL = "https://www.afnic.fr/wp-media/ftp/domaineTLD_Afnic/{stamp}_CREA_{tld}.txt"
_CREA_TLDS = ("fr", "re", "pm", "tf", "wf", "yt")
_CREA_HEADER = b"domain;tld;creation_date\n"


async def creations(ctx: Context) -> None:
    """Rolling window of the newest AFNIC domain creations, one file per day upstream.

    AFNIC publishes creations only - there is no matching deletion feed - so the window is
    rebuilt from scratch on every run instead of being merged into the previous output: a
    day that drops out simply stops being fetched, and nothing can drift. Note that a domain
    listed here may already have been dropped again; the monthly open data stays the
    authority on what is currently registered.

    The current day is never published yet (AFNIC lags about a day) and some days are
    missing for a given TLD, so the walk goes back from today until `days` days that carry
    a .fr file have been collected, giving up after `lookback` calendar days.
    """
    days = int(ctx.options.get("days", 7))
    lookback = int(ctx.options.get("lookback", days + 7))
    tlds = tuple(ctx.options.get("tlds", _CREA_TLDS))
    min_domains = int(ctx.options.get("min_domains", 10_000))

    newest: dict[str, tuple[str, str]] = {}  # domain -> (creation date, tld)
    window: list[str] = []
    today = date.today()
    for back in range(lookback):
        if len(window) == days:
            break
        day = today - timedelta(days=back)
        stamp = f"{day:%Y%m%d}"
        found = await asyncio.gather(*(_crea_day(ctx, stamp, t) for t in tlds))
        if found[0] is None:  # no .fr file: that day is not published (yet)
            logger.debug("[afnic] %s not published", stamp)
            continue
        window.append(f"{day:%Y-%m-%d}")
        for tld, domains in zip(tlds, found):
            if domains is None:
                ctx.errors.append(f"{stamp}_CREA_{tld}.txt unavailable")
                continue
            for domain in domains:
                # Walking newest first, the first date met for a domain is the one to keep.
                newest.setdefault(domain, (f"{day:%Y-%m-%d}", tld))

    if len(window) < days:
        ctx.errors.append(f"only {len(window)} of the {days} requested days were available")
    if len(newest) < min_domains:
        raise ValueError(f"only {len(newest)} creations over {window or 'no day'} "
                         f"(min {min_domains})")

    target = ctx.path(ctx.source.output)
    with target.open("wb") as fh:
        fh.write(_CREA_HEADER)
        for domain in sorted(newest):  # sorted: identical content -> identical bytes
            created, tld = newest[domain]
            fh.write(f"{domain};{tld};{created}\n".encode())
    ctx.state["window"] = sorted(window)
    logger.info("[afnic] %d creations over %d days (%s -> %s)",
                len(newest), len(window), min(window, default="-"), max(window, default="-"))


async def _crea_day(ctx: Context, stamp: str, tld: str) -> list[str] | None:
    """The day's creations for one TLD, or None when AFNIC has no such file."""
    url = _CREA_URL.format(stamp=stamp, tld=tld)
    try:
        body = await get_text(ctx.client, url, attempts=ctx.source.retries,
                              headers=ctx.source.resolved_headers())
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return None
        raise
    # Free-text licence header, then #BOF, one domain per line, then #EOF.
    return [line.strip() for line in body.splitlines()
            if line.strip() and not line.startswith("#")]
