"""Fetch engine: run sources concurrently, validate, publish atomically, track state.

Guarantees:
- a source is all-or-nothing: its files are validated first, published only if all pass;
- a failed source keeps its previous files (status reported in catalog.json / README);
- processors may publish what succeeded and report the rest (status "partial");
- failed sources get a second, sequential pass after a cool-down (flaky hosts).
"""

from __future__ import annotations

import asyncio
import copy
import fnmatch
import gzip
import hashlib
import lzma
import json
import logging
import shutil
import tempfile
import time
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .catalog import Source
from .http import FetchMeta, NotModified, download, make_client
from .validate import MAX_FILE_BYTES, ValidationError, count_records, validate

logger = logging.getLogger("cybref")

STATE = ".cybref/state.json"
PUBLIC_CATALOG = "catalog.json"
RESERVED = {".cybref", PUBLIC_CATALOG, "README.md", ".git", ".github", ".gitattributes"}
RETRY_COOLDOWN = 60.0
# Leave headroom under the publication limit: a shard landing exactly on it fails the run.
SHARD_LIMIT = int(MAX_FILE_BYTES * 0.8)


# --------------------------------------------------------------------------- file helpers


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(8 << 20):
            h.update(chunk)
    return h.hexdigest()


@contextmanager
def gzip_open_write(path: Path, level: int = 6):
    """Deterministic gzip (no name, mtime=0): identical content -> identical bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw, gzip.GzipFile(
        filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=level
    ) as gz:
        yield gz


def gzip_file(src: Path, dst: Path) -> None:
    with src.open("rb") as fin, gzip_open_write(dst) as fout:
        shutil.copyfileobj(fin, fout, 8 << 20)


def gunzip_file(src: Path, dst: Path) -> None:
    with src.open("rb") as fh:
        magic = fh.read(2)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if magic != b"\x1f\x8b":  # already decoded by the HTTP layer
        shutil.move(src, dst)
        return
    with gzip.open(src, "rb") as fin, dst.open("wb") as fout:
        shutil.copyfileobj(fin, fout, 8 << 20)


XZ_MAGIC = bytes.fromhex("fd377a585a00")


def unxz_file(src: Path, dst: Path) -> None:
    with src.open("rb") as fh:
        magic = fh.read(6)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if magic != XZ_MAGIC:  # already decoded by the HTTP layer
        shutil.move(src, dst)
        return
    with lzma.open(src, "rb") as fin, dst.open("wb") as fout:
        shutil.copyfileobj(fin, fout, 8 << 20)


def zstd_open(path: Path):
    """Read handle on a .zst file. Python 3.14 ships `compression.zstd`; older
    interpreters fall back to the `zstandard` wheel declared in pyproject."""
    try:
        from compression import zstd
    except ImportError:
        import zstandard

        return zstandard.ZstdDecompressor().stream_reader(path.open("rb"))
    return zstd.open(path, "rb")


def unzip_member(src: Path, dst: Path, member: str | None) -> None:
    with zipfile.ZipFile(src) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        if member:
            names = [n for n in names if fnmatch.fnmatch(n, member) or n.rsplit("/", 1)[-1] == member]
        if len(names) != 1:
            raise ValueError(f"zip: expected one member matching {member!r}, found {names[:5]}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(names[0]) as fin, dst.open("wb") as fout:
            shutil.copyfileobj(fin, fout, 8 << 20)


class ShardWriter:
    """Write a JSON array across as many gzipped shards as the size limit requires.

    A single array is the nicest thing to consume, but GitHub refuses files over 100 MB
    and the published corpora (Ubuntu advisories, a busy CVE year, Red Hat's VEX) pass it.
    Splitting on a record count does not work: record sizes vary by two orders of
    magnitude, so equal counts give wildly unequal files. This rolls over on the
    compressed bytes actually written, which also makes the cut deterministic - the same
    records in the same order always land in the same shards, so the engine republishes
    only what really moved.

    `name(i)` returns the path of shard *i* (1-based); rows are raw JSON, no separators.
    """

    def __init__(self, name, limit: int = SHARD_LIMIT):
        self._name = name
        self._limit = limit
        self._index = 0
        self._raw = None
        self._gz = None
        self._rows = 0
        self.shards: list[Path] = []

    def _open(self) -> None:
        self._index += 1
        path = self._name(self._index)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._raw = path.open("wb")
        self._gz = gzip.GzipFile(filename="", mode="wb", fileobj=self._raw, mtime=0)
        self._gz.write(b"[")
        self._rows = 0
        self.shards.append(path)

    def _close_shard(self) -> None:
        if self._gz is None:
            return
        self._gz.write(b"]")
        self._gz.close()
        self._raw.close()
        self._gz = self._raw = None

    def write(self, row: bytes) -> None:
        if self._gz is None:
            self._open()
        elif self._rows and self._raw.tell() >= self._limit:
            # tell() trails the deflate buffer by at most a few KB, which the margin
            # between the limit and GitHub's own covers.
            self._close_shard()
            self._open()
        self._gz.write((b"," if self._rows else b"") + row)
        self._rows += 1

    def close(self) -> int:
        self._close_shard()
        return self._index

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def write_json(path: Path, obj, *, indent: int | None = None) -> None:
    """JSON writer; `.gz` suffix -> deterministic gzip."""
    text = json.dumps(obj, ensure_ascii=False, indent=indent, default=str,
                      separators=None if indent else (",", ":"))
    if path.name.endswith(".gz"):
        with gzip_open_write(path) as fh:
            fh.write(text.encode("utf-8"))
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def is_pattern(name: str) -> bool:
    return any(c in name for c in "*?[")


# --------------------------------------------------------------------------- context


@dataclass
class Context:
    """What a processor gets: a staging dir for its outputs plus helpers."""

    source: Source
    client: httpx.AsyncClient
    out_dir: Path
    stage: Path
    work: Path
    state: dict
    use_cache: bool
    force: bool = False
    errors: list[str] = field(default_factory=list)  # non-fatal: publish the rest, status "partial"

    @property
    def options(self) -> dict:
        return self.source.options

    def path(self, rel: str) -> Path:
        p = self.stage / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def published(self, rel: str) -> Path:
        return self.out_dir / rel

    def write_json(self, rel: str, obj, *, indent: int | None = None) -> None:
        write_json(self.path(rel), obj, indent=indent)

    async def download(self, url: str, dest: Path | None = None, *, cache: bool = False) -> Path:
        """Download to *dest* (default: work dir). cache=True -> conditional GET (may raise NotModified)."""
        dest = dest or self.work / f"dl-{hashlib.md5(url.encode()).hexdigest()[:10]}"
        http_state = self.state.setdefault("http", {})
        cached = http_state.get(url, {}) if cache and self.use_cache else {}
        meta: FetchMeta = await download(
            self.client, url, dest,
            headers=self.source.resolved_headers(),
            etag=cached.get("etag"),
            last_modified=cached.get("last_modified"),
            attempts=self.source.retries,
        )
        if cache:
            http_state[url] = {k: v for k, v in (("etag", meta.etag), ("last_modified", meta.last_modified)) if v}
        return dest


# --------------------------------------------------------------------------- results


@dataclass
class Result:
    source: Source
    status: str  # updated | unchanged | not_modified | partial | failed
    changed: list[str] = field(default_factory=list)
    error: str | None = None
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status not in ("failed", "partial")


# --------------------------------------------------------------------------- engine


class Engine:
    def __init__(self, out_dir: Path, *, concurrency: int = 6, force: bool = False):
        self.out_dir = out_dir
        self.concurrency = concurrency
        self.force = force
        self.state = self._load_state()

    def _load_state(self) -> dict:
        path = self.out_dir / STATE
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data.get("sources"), dict):
                    return data
            except ValueError:
                logger.warning("Corrupted %s, starting fresh", path)
        return {"sources": {}}

    def save_state(self) -> None:
        self.state["generated_at"] = now_iso()
        self.state["sources"] = dict(sorted(self.state["sources"].items()))
        write_json(self.out_dir / STATE, self.state, indent=1)

    async def run(self, sources: list[Source], retry_failed: bool = True) -> list[Result]:
        from .processors import PROCESSORS, plain_download

        self.out_dir.mkdir(parents=True, exist_ok=True)
        tmp_root = Path(tempfile.mkdtemp(prefix="cybref-"))

        def fn_for(src: Source):
            return PROCESSORS[src.processor] if src.processor else plain_download

        try:
            async with make_client() as client:
                sem = asyncio.Semaphore(self.concurrency)

                async def guarded(src: Source) -> Result:
                    async with sem:
                        return await self._run_one(src, fn_for(src), client, tmp_root)

                results = {r.source.id: r for r in await asyncio.gather(*(guarded(s) for s in sources))}

                retry = [r.source for r in results.values() if r.status == "failed"]
                if retry and retry_failed:
                    logger.info("Second pass for %d failed source(s) in %.0fs: %s",
                                len(retry), RETRY_COOLDOWN, ", ".join(s.id for s in retry))
                    await asyncio.sleep(RETRY_COOLDOWN)
                    for src in retry:  # sequential: gentler on the hosts that failed
                        results[src.id] = await self._run_one(src, fn_for(src), client, tmp_root)
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
            self.save_state()
        return [results[s.id] for s in sources]

    async def _run_one(self, src: Source, fn, client, tmp_root: Path) -> Result:
        prev = self.state["sources"].get(src.id, {})
        base = tmp_root / src.id
        shutil.rmtree(base, ignore_errors=True)
        stage, work = base / "stage", base / "work"
        stage.mkdir(parents=True)
        work.mkdir(parents=True)
        fixed_outputs = [o for o in src.outputs if not is_pattern(o)]
        ctx = Context(
            source=src, client=client, out_dir=self.out_dir, stage=stage, work=work,
            state=copy.deepcopy(prev.get("state", {})), force=self.force,
            use_cache=(
                not self.force
                and prev.get("fingerprint") == src.fingerprint()
                and all((self.out_dir / o).is_file() for o in fixed_outputs)
            ),
        )
        logger.info("[%s] start", src.id)
        t0 = time.monotonic()
        entry = {**prev, "last_attempt": now_iso()}
        try:
            await fn(ctx)
            changed = await asyncio.to_thread(self._publish, src, stage, prev)
            missing = [o for o in fixed_outputs if not (self.out_dir / o).is_file()]
            if missing:
                raise ValidationError(f"expected outputs missing: {missing}")
            if ctx.errors:
                result = Result(src, "partial", changed, error="; ".join(ctx.errors)[:600])
            else:
                result = Result(src, "updated" if changed else "unchanged", changed)
            entry["state"] = ctx.state
            entry["fingerprint"] = src.fingerprint()
        except NotModified:
            result = Result(src, "not_modified")
        except Exception as exc:  # noqa: BLE001 - one bad source must not stop the run
            result = Result(src, "failed", error=_describe(exc))
            logger.debug("[%s] traceback", src.id, exc_info=True)
        finally:
            shutil.rmtree(base, ignore_errors=True)

        result.duration = time.monotonic() - t0
        entry["status"] = result.status
        entry["duration_s"] = round(result.duration, 1)
        if result.error:
            entry["error"] = result.error
            logger.error("[%s] %s: %s", src.id, result.status.upper(), result.error)
        else:
            entry.pop("error", None)
        if result.status != "failed":
            entry["last_success"] = entry["last_attempt"]
            if result.changed:
                entry["last_change"] = entry["last_attempt"]
            entry["files"] = await asyncio.to_thread(
                self._files_info, src, prev.get("files", {}), result.changed
            )
            logger.info("[%s] %s in %.1fs%s", src.id, result.status, result.duration,
                        f" ({len(result.changed)} file(s) changed)" if result.changed else "")
        self.state["sources"][src.id] = entry
        return result

    def _publish(self, src: Source, stage: Path, prev: dict) -> list[str]:
        """Validate every staged file, then move changed ones into out_dir."""
        staged = sorted(p for p in stage.rglob("*") if p.is_file())
        prev_files = prev.get("files", {})
        plan: list[tuple[Path, Path, str]] = []
        for path in staged:
            rel = path.relative_to(stage).as_posix()
            target = self.out_dir / rel
            validate(
                path,
                min_bytes=src.min_bytes,
                min_lines=src.min_lines,
                previous_size=None if self.force or not target.is_file() else target.stat().st_size,
                shrink_guard=src.shrink_guard,
            )
            digest = sha256_file(path)
            known = prev_files.get(rel, {}).get("sha256")
            if target.is_file() and (known == digest or (known is None and sha256_file(target) == digest)):
                continue
            plan.append((path, target, rel))
        # Only touch out_dir once everything validated: a source updates all-or-nothing.
        for path, target, _ in plan:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(path, target)
        return [rel for _, _, rel in plan]

    def _files_info(self, src: Source, prev_files: dict, changed: list[str]) -> dict:
        files: dict[str, dict] = {}
        for rel in self._existing_outputs(src):
            path = self.out_dir / rel
            info = prev_files.get(rel)
            size = path.stat().st_size
            if rel in changed or not info or info.get("bytes") != size:
                info = {"bytes": size, "sha256": sha256_file(path), "records": count_records(path),
                        "updated": now_iso()}
            files[rel] = info
        return dict(sorted(files.items()))

    def _existing_outputs(self, src: Source) -> list[str]:
        found: list[str] = []
        for pattern in src.outputs:
            if is_pattern(pattern):
                found.extend(sorted(p.relative_to(self.out_dir).as_posix()
                                    for p in self.out_dir.glob(pattern) if p.is_file()))
            elif (self.out_dir / pattern).is_file():
                found.append(pattern)
        return found

    def prune(self, sources: list[Source], dry_run: bool = False) -> list[str]:
        """Delete published files that no catalog entry produces anymore."""
        patterns = [o for s in sources for o in s.outputs]
        removed: list[str] = []
        for path in sorted(self.out_dir.rglob("*")):
            rel = path.relative_to(self.out_dir).as_posix()
            if not path.is_file() or rel.split("/", 1)[0] in RESERVED:
                continue
            if any(fnmatch.fnmatch(rel, p) for p in patterns):
                continue
            removed.append(rel)
            if not dry_run:
                path.unlink()
        known = {s.id for s in sources}
        for sid in [k for k in self.state["sources"] if k not in known]:
            removed.append(f"(state) {sid}")
            if not dry_run:
                del self.state["sources"][sid]
        if not dry_run:
            for d in sorted((p for p in self.out_dir.rglob("*") if p.is_dir()), reverse=True):
                if ".git" not in d.parts and not any(d.iterdir()):
                    d.rmdir()
            self.save_state()
        return removed


def _describe(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code} on {exc.request.url}"
    if isinstance(exc, httpx.HTTPError):
        try:
            where = f" on {exc.request.url}"
        except RuntimeError:
            where = ""
        return f"{type(exc).__name__}{where}: {exc}"
    msg = str(exc) or type(exc).__name__
    return msg if len(msg) < 400 else msg[:400] + "..."
