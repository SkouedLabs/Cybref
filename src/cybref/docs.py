"""Generated docs: README catalog section, data README, public catalog.json, run summary."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from .catalog import CATEGORIES, Source
from .engine import Result
from .validate import detect_format

FREQ = {"frequent": "2-hourly", "daily": "Daily", "weekly": "Weekly", "mobile": "Weekly"}
STALE_DAYS = {"frequent": 1, "daily": 3, "weekly": 15, "mobile": 15}
_START, _END = "<!-- catalog:start -->", "<!-- catalog:end -->"


def raw_base(repo: str, branch: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{branch}"


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _host(url: str) -> str:
    return re.sub(r"^https?://(www\.)?", "", url).split("/")[0]


def _file_cell(src: Source, base: str) -> str:
    links = []
    for out in src.outputs:
        if any(c in out for c in "*?["):
            links.append(f"`{out.split('/', 1)[1]}`")
        else:
            links.append(f"[`{out.split('/', 1)[1]}`]({base}/{out})")
    return "<br>".join(links)


def catalog_markdown(sources: list[Source], repo: str, branch: str, state: dict | None = None) -> str:
    base = raw_base(repo, branch)
    by_cat: dict[str, list[Source]] = {}
    for s in sources:
        by_cat.setdefault(s.category, []).append(s)

    lines: list[str] = []
    for cat, title in CATEGORIES.items():
        items = by_cat.get(cat)
        if not items:
            continue
        lines += [f"### {title} - `{cat}/`", ""]
        if state is None:
            lines += ["| File | Freq | Description | Source |", "| :--- | :--- | :--- | :--- |"]
        else:
            lines += ["| File | Freq | Size | Updated | Description | Source |",
                      "| :--- | :--- | ---: | :--- | :--- | :--- |"]
        for s in items:
            row = [_file_cell(s, base), FREQ[s.group]]
            if state is not None:
                entry = state.get("sources", {}).get(s.id, {})
                size = sum(f.get("bytes", 0) for f in entry.get("files", {}).values())
                row += [_fmt_size(size) if size else "-", _status_cell(s, entry)]
            row += [f"**{s.name}**. {s.description.strip()}", f"[{_host(s.homepage)}]({s.homepage})"]
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def health(src: Source, entry: dict) -> str:
    """ok | degraded (last run failed/partial or overdue, previous data kept) | missing."""
    if not entry.get("last_success"):
        return "missing"
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(entry["last_success"])).days
    if entry.get("status") in ("failed", "partial") or age > STALE_DAYS[src.group]:
        return "degraded"
    return "ok"


def _status_cell(src: Source, entry: dict) -> str:
    changed = (entry.get("last_change") or entry.get("last_success") or "")[:10]
    return {"missing": "❌ never", "degraded": f"⚠️ {changed}"}.get(health(src, entry), changed)


def public_catalog(sources: list[Source], state: dict, repo: str, branch: str) -> dict:
    """catalog.json - the reference of the references: what exists, how fresh, how big."""
    base = raw_base(repo, branch)
    datasets = []
    total_bytes = total_files = 0
    by_health: dict[str, list[str]] = {}
    for s in sources:
        entry = state.get("sources", {}).get(s.id, {})
        files = []
        for rel, info in entry.get("files", {}).items():
            files.append({
                "path": rel,
                "url": f"{base}/{rel}",
                "format": detect_format(rel),
                "compressed": rel.endswith(".gz"),
                "bytes": info.get("bytes"),
                "records": info.get("records"),
                "sha256": info.get("sha256"),
                "updated": info.get("updated"),
            })
            total_bytes += info.get("bytes") or 0
        total_files += len(files)
        h = health(s, entry)
        by_health.setdefault(h, []).append(s.id)
        datasets.append({
            "id": s.id,
            "name": s.name,
            "category": s.category,
            "category_title": CATEGORIES[s.category],
            "frequency": FREQ[s.group].lower(),
            "description": s.description.strip(),
            "homepage": s.homepage,
            "origin": s.resolved_urls() or None,
            "health": h,
            "last_run": {
                "status": entry.get("status"),
                "at": entry.get("last_attempt"),
                "duration_s": entry.get("duration_s"),
                "error": entry.get("error"),
            },
            "last_success": entry.get("last_success"),
            "last_change": entry.get("last_change"),
            "bytes": sum(f["bytes"] or 0 for f in files),
            "files": files,
        })
    return {
        "generated_at": state.get("generated_at"),
        "repository": f"https://github.com/{repo}",
        "raw_base": base,
        "summary": {
            "datasets": len(datasets),
            "files": total_files,
            "bytes": total_bytes,
            "health": {k: len(v) for k, v in sorted(by_health.items())},
            "degraded": sorted(by_health.get("degraded", []) + by_health.get("missing", [])),
        },
        "datasets": datasets,
    }


def update_readme(readme: Path, sources: list[Source], repo: str, branch: str) -> bool:
    text = readme.read_text(encoding="utf-8")
    if _START not in text or _END not in text:
        raise ValueError(f"{readme}: missing {_START} / {_END} markers")
    head, rest = text.split(_START, 1)
    _, tail = rest.split(_END, 1)
    new = f"{head}{_START}\n{catalog_markdown(sources, repo, branch)}{_END}{tail}"
    if new != text:
        readme.write_text(new, encoding="utf-8")
        return True
    return False


def data_readme(sources: list[Source], state: dict, repo: str, branch: str) -> str:
    return f"""# 🛡️ Cybref - Cybersecurity Reference Sets

Automated mirror of cybersecurity reference datasets: threat-intel feeds, Living Off The Land
projects, vulnerability databases, network ranges and hardware registries - downloaded,
validated and normalized on a schedule.

## Usage

Single file: `{raw_base(repo, branch)}/<file>`

Everything:

```bash
git clone --depth 1 https://github.com/{repo}.git cybref
# update later (history is not kept: the branch is a single commit replaced at each update)
git -C cybref fetch --depth 1 origin {branch} && git -C cybref reset --hard origin/{branch}
```

[`catalog.json`]({raw_base(repo, branch)}/catalog.json) is the machine-readable index of
everything here: per dataset its description, source, frequency, health and last run, and per
file its URL, size, record count, sha256 and last update.

Last generated {(state.get("generated_at") or "")[:16].replace("T", " ")} UTC.
⚠️ = last update failed or is overdue - the previous version of the file is kept.

The tooling lives on the [`download`](https://github.com/{repo}/tree/download) branch.

## Catalog

{catalog_markdown(sources, repo, branch, state)}
## Disclaimer

Data belongs to its respective sources, which deserve all the credit. This repository only
mirrors it: check each source's license before any commercial or production use.
"""


def run_summary(results: list[Result]) -> str:
    icon = {"updated": "🟢", "unchanged": "⚪", "not_modified": "⚪", "partial": "🟠", "failed": "🔴"}
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    lines = [
        "## Cybref run",
        "",
        " · ".join(f"{icon[k]} {k}: {v}" for k, v in sorted(counts.items())),
        "",
        "| | Source | Status | Time | Detail |",
        "| :-- | :-- | :-- | --: | :-- |",
    ]
    order = {"failed": 0, "partial": 1, "updated": 2, "unchanged": 3, "not_modified": 4}
    for r in sorted(results, key=lambda r: (order[r.status], r.source.id)):
        detail = r.error or (", ".join(r.changed[:3]) + (" …" if len(r.changed) > 3 else ""))
        lines.append(f"| {icon[r.status]} | `{r.source.id}` | {r.status} | {r.duration:.0f}s | {detail.replace('|', '/')} |")
    return "\n".join(lines) + "\n"
