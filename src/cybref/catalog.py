"""Load and validate the dataset catalog (sources.yaml)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import date, timedelta
from pathlib import Path

import yaml

GROUPS = ("frequent", "daily", "weekly", "mobile")
EXTRACTS = (None, "gunzip", "unzip")

# Category = top-level folder of the published files.
CATEGORIES = {
    "threat_intel": "Threat Intelligence & IOCs",
    "lol": "Living Off The Land",
    "vulnerabilities": "Vulnerabilities & Exploits",
    "frameworks": "Frameworks & Knowledge Bases",
    "network": "Network: Cloud, ASN, Geo, Anonymizers, Crawlers",
    "domains": "Domains & Email",
    "registries": "Standards & Hardware Registries",
    "detection": "Detection Lists & Allowlists",
}

# Naming convention: <category>/<provider>_<dataset>[_<variant>].<ext>[.gz]
# lowercase snake_case, the file stem is the source id, the extension tells the real format.
EXTENSIONS = ("json", "jsonl", "csv", "tsv", "txt", "xml", "yaml", "pem")
_SEGMENT_RE = re.compile(r"^[a-z0-9*][a-z0-9_.*?\[\]-]*$")
_ID_RE = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*$")

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)

BROWSER_HEADERS = {
    "User-Agent": BROWSER_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/csv,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


@dataclass
class Source:
    id: str
    name: str
    group: str
    homepage: str
    description: str
    outputs: list[str]
    urls: list[str] = field(default_factory=list)
    extract: str | None = None
    member: str | None = None
    compress: bool = False
    min_bytes: int = 20
    min_lines: int = 1
    shrink_guard: float = 0.5
    retries: int = 5
    headers: dict[str, str] = field(default_factory=dict)
    user_agent: str | None = None
    encoding: str | None = None  # source charset to re-encode as UTF-8 (e.g. utf-16)
    processor: str | None = None
    options: dict = field(default_factory=dict)

    @property
    def output(self) -> str:
        return self.outputs[0]

    @property
    def category(self) -> str:
        return self.outputs[0].split("/", 1)[0]

    def resolved_urls(self, today: date | None = None) -> list[str]:
        """Expand {today:%Y-%m} / {last_month:%Y-%m} / {month_2:%Y-%m} / {month_3:%Y-%m}.

        month_2 and month_3 reach two and three months back, for publishers whose lag is
        longer than a month or simply irregular: AFNIC's monthly open data is routinely
        still two months behind, and a two-URL chain leaves the source failing until it lands.
        """
        today = today or date.today()
        months = [today]
        for _ in range(3):
            months.append(months[-1].replace(day=1) - timedelta(days=1))
        return [u.format(today=today, last_month=months[1],
                         month_2=months[2], month_3=months[3]) for u in self.urls]

    def resolved_headers(self) -> dict[str, str]:
        """Substitute ${ENV} values; drop headers whose variable is unset."""
        out: dict[str, str] = {}
        for key, value in self.headers.items():
            missing = [v for v in _ENV_RE.findall(value) if not os.environ.get(v)]
            if missing:
                continue
            out[key] = _ENV_RE.sub(lambda m: os.environ[m.group(1)], value)
        if self.user_agent == "browser":
            out.update(BROWSER_HEADERS)
        elif self.user_agent:
            out["User-Agent"] = self.user_agent
        return out

    def fingerprint(self) -> str:
        """Hash of the fetch config: a changed config must bypass HTTP caching."""
        raw = json.dumps(asdict(self), sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class CatalogError(ValueError):
    pass


def load_catalog(path: Path) -> list[Source]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("sources"), dict):
        raise CatalogError(f"{path}: expected a top-level 'sources' mapping")

    sources: list[Source] = []
    seen_outputs: dict[str, str] = {}
    for sid, spec in raw["sources"].items():
        if not isinstance(spec, dict):
            raise CatalogError(f"{sid}: entry must be a mapping")
        spec = dict(spec)
        urls = spec.pop("url", None)
        outputs = spec.pop("output", None)
        src = Source(
            id=sid,
            urls=[urls] if isinstance(urls, str) else list(urls or []),
            outputs=[outputs] if isinstance(outputs, str) else list(outputs or []),
            **spec,
        )
        _check(src)
        for out in src.outputs:
            if out in seen_outputs:
                raise CatalogError(f"{sid}: output {out!r} already produced by {seen_outputs[out]}")
            seen_outputs[out] = sid
        sources.append(src)
    return sources


def _check(src: Source) -> None:
    err = lambda msg: CatalogError(f"{src.id}: {msg}")  # noqa: E731
    if not _ID_RE.match(src.id):
        raise err("id must be lowercase snake_case")
    if src.group not in GROUPS:
        raise err(f"group must be one of {GROUPS}")
    if src.extract not in EXTRACTS:
        raise err(f"extract must be one of {EXTRACTS}")
    if not src.outputs:
        raise err("missing 'output'")
    for out in src.outputs:
        parts = out.split("/")
        if len(parts) < 2 or parts[0] not in CATEGORIES:
            raise err(f"{out!r} must live in a category folder: {tuple(CATEGORIES)}")
        if parts[0] != src.category:
            raise err("all outputs of a source must share one category folder")
        if not all(_SEGMENT_RE.match(p) for p in parts):
            raise err(f"{out!r}: lowercase letters, digits, _ . - only")
        base = parts[-1].removesuffix(".gz")
        if base.rsplit(".", 1)[-1] not in EXTENSIONS:
            raise err(f"{out!r}: extension must be one of {EXTENSIONS} (+ .gz)")
    if len(src.outputs) == 1 and not any(c in src.output for c in "*?["):
        stem = src.output.rsplit("/", 1)[-1].removesuffix(".gz").rsplit(".", 1)[0]
        if stem != src.id:
            raise err(f"file stem {stem!r} must equal the source id")
    if not src.processor:
        if not src.urls:
            raise err("missing 'url' (or a 'processor')")
        if len(src.outputs) != 1:
            raise err("plain downloads produce exactly one output")
    if src.compress and not src.output.endswith(".gz"):
        raise err("compressed output must end with .gz")
