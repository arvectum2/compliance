"""CLI for offline HTML and explicitly authorized static URL scans."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.scan import scan_html


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arvectum-compliance")
    sub = parser.add_subparsers(dest="command", required=True)
    offline = sub.add_parser("scan-html", help="Offline scan of a local HTML file")
    offline.add_argument("file", type=Path)
    offline.add_argument("--url", required=True, help="Source URL for report evidence")
    online = sub.add_parser("scan-url", help="Bounded HTTP GET; no redirects or JavaScript")
    online.add_argument("url")
    online.add_argument(
        "--authorized", action="store_true",
        help="I control this site or have permission to scan it",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "scan-html":
            if args.file.stat().st_size > 2_000_000:
                raise ValueError("HTML file exceeds 2 MB limit")
            report = scan_html(args.url, args.file.read_text(encoding="utf-8"))
        else:
            if not args.authorized:
                raise PermissionError("Pass --authorized only for a site you may scan")
            from .adapters.data_platform import scan_url

            report = scan_url(args.url, authorized=True)
    except (ValueError, PermissionError, OSError, ImportError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
