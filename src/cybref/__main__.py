"""cybref CLI.

    cybref fetch --group daily --out data      download a group of sources
    cybref fetch --only cisa_kev,epss          download specific sources
    cybref list                                show the catalog
    cybref docs                                regenerate the README catalog section
    cybref prune --out data                    delete files no source produces anymore
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from .catalog import GROUPS, CatalogError, load_catalog
from .docs import data_readme, public_catalog, run_summary, update_readme
from .engine import PUBLIC_CATALOG, Engine, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cybref", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--catalog", type=Path, default=Path("sources.yaml"))
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "SkouedLabs/Cybref"),
                        help="owner/name used for links (default: $GITHUB_REPOSITORY)")
    parser.add_argument("--data-branch", default="main")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_fetch = sub.add_parser("fetch", help="download sources")
    p_fetch.add_argument("--out", type=Path, default=Path("data"))
    p_fetch.add_argument("--group", action="append", choices=GROUPS,
                         help="repeatable; default: every group")
    p_fetch.add_argument("--only", help="comma-separated source ids")
    p_fetch.add_argument("--concurrency", type=int, default=6)
    p_fetch.add_argument("--force", action="store_true",
                         help="ignore HTTP caches and shrink guards (mobile: rebuild from scratch)")
    p_fetch.add_argument("--no-retry", action="store_true", help="skip the second pass on failed sources")

    p_list = sub.add_parser("list", help="show the catalog")
    p_list.add_argument("--group", action="append", choices=GROUPS)

    p_docs = sub.add_parser("docs", help="regenerate the catalog section of README.md")
    p_docs.add_argument("--readme", type=Path, default=Path("README.md"))

    p_prune = sub.add_parser("prune", help="delete published files that no source produces")
    p_prune.add_argument("--out", type=Path, default=Path("data"))
    p_prune.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")  # emoji in summaries
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    try:
        sources = load_catalog(args.catalog)
    except (OSError, CatalogError) as exc:
        print(f"catalog error: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "list":
        for s in sources:
            if not args.group or s.group in args.group:
                print(f"{s.group:7} {s.category:16} {s.id:32} {', '.join(s.outputs)}")
        return 0

    if args.cmd == "docs":
        changed = update_readme(args.readme, sources, args.repo, args.data_branch)
        print(f"{args.readme}: {'updated' if changed else 'up to date'}")
        return 0

    if args.cmd == "prune":
        removed = Engine(args.out).prune(sources, dry_run=args.dry_run)
        for rel in removed:
            print(("would remove " if args.dry_run else "removed ") + rel)
        return 0

    selected = sources
    if args.only:
        ids = {i.strip() for i in args.only.split(",") if i.strip()}
        unknown = ids - {s.id for s in sources}
        if unknown:
            print(f"unknown source(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        selected = [s for s in selected if s.id in ids]
    if args.group:
        selected = [s for s in selected if s.group in args.group]
    if not selected:
        print("nothing to fetch", file=sys.stderr)
        return 2

    engine = Engine(args.out, concurrency=args.concurrency, force=args.force)
    results = asyncio.run(engine.run(selected, retry_failed=not args.no_retry))

    write_json(args.out / PUBLIC_CATALOG, public_catalog(sources, engine.state, args.repo, args.data_branch), indent=2)
    (args.out / "README.md").write_text(
        data_readme(sources, engine.state, args.repo, args.data_branch), encoding="utf-8"
    )
    summary = run_summary(results)
    print(summary)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(summary)
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
