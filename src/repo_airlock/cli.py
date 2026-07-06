"""Command-line interface for repo-airlock."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from repo_airlock import __version__
from repo_airlock.baseline import write_baseline
from repo_airlock.findings import Severity
from repo_airlock.report import render_console, render_json, render_markdown
from repo_airlock.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airlock",
        description=(
            "repo-airlock: pre-publication scanner. Scans a directory (and optionally "
            "git history) for secrets, privacy leaks, and publication hygiene issues "
            "before you make a repo public."
        ),
    )
    parser.add_argument("--version", action="version", version=f"repo-airlock {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a directory before publishing it.")
    scan_parser.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current directory)")
    scan_parser.add_argument(
        "--history", action="store_true", help="Also scan full git history (requires a git repo)."
    )
    scan_parser.add_argument(
        "--format", choices=["console", "md", "json"], default="console", help="Output format (default: console)."
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high"],
        default="high",
        help="Minimum severity that causes a nonzero exit code (default: high).",
    )
    scan_parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Path to a baseline JSON file of acknowledged findings to suppress.",
    )
    scan_parser.add_argument(
        "--write-baseline",
        type=Path,
        default=None,
        help="Write current findings as a new baseline file at this path, instead of failing on them.",
    )
    scan_parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI color in console output."
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)

    parser.print_help()
    return 1


def _run_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.is_dir():
        print(f"error: '{args.path}' is not a directory", file=sys.stderr)
        return 2

    fail_on = Severity.from_str(args.fail_on)

    result = scan(root, include_history=args.history, baseline_path=args.baseline)

    if args.write_baseline is not None:
        write_baseline(args.write_baseline, result.findings)
        print(f"Wrote baseline with {len(result.findings)} finding(s) to {args.write_baseline}")
        return 0

    if args.format == "json":
        print(render_json(result, fail_on=fail_on), end="")
    elif args.format == "md":
        print(render_markdown(result, fail_on=fail_on), end="")
    else:
        use_color = (not args.no_color) and sys.stdout.isatty()
        print(render_console(result, fail_on=fail_on, use_color=use_color))

    return result.exit_code(fail_on)


if __name__ == "__main__":
    sys.exit(main())
