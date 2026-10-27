"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Set

from . import __version__
from .detector import Scanner, ScanResult, iter_targets
from .reporter import render_json, render_sarif, render_text
from .rules import CRITICAL, HIGH, LOW, MEDIUM, RULES, SEVERITY_ORDER, Rule
from .rules import RULE_FOR_CODEPOINT

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def force_utf8_stdio() -> None:
    """Force UTF-8 on all three standard streams.

    Windows defaults stdout to cp1252 (or another legacy codepage), which
    cannot encode the very characters this tool reports -- U+200B, Cyrillic
    homographs, tag characters. Without this, InvisiScan dies with a
    UnicodeEncodeError *while printing its own findings*, which ironically
    turns every detection into a crash. Reading stdin as UTF-8 matters just as
    much: `cat file | invisiscan --stdin` would otherwise mojibake or fail.

    ``backslashreplace`` on the output streams is a belt-and-braces measure so
    a hostile redirect can never take the scanner down mid-report.
    """
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                if name == "stdin":
                    reconfigure(encoding="utf-8", errors="replace")
                else:
                    reconfigure(encoding="utf-8", errors="backslashreplace")
            except (ValueError, OSError, TypeError):
                # Non-reconfigurable stream (redirected, replaced by test
                # harness, etc.) -- nothing further we can do, so carry on.
                pass


class _ArgParser(argparse.ArgumentParser):
    """Keeps usage output compact without losing -h behaviour."""

    def format_help(self) -> str:
        base = super().format_help()
        listing = "\n".join(
            "  {:<7} {:<22} {}".format(r.rule_id, r.name, r.severity) for r in RULES
        )
        listing += "\n  {:<7} {:<22} {}".format("IS010", "confusable-identifier", HIGH)
        listing += "\n  {:<7} {:<22} {}".format("IS011", "noncharacter", MEDIUM)
        return base + "\nrule catalogue:\n" + listing + "\n"


def build_parser() -> _ArgParser:
    parser = _ArgParser(
        prog="invisiscan",
        description=(
            "Detect invisible characters, Unicode direction controls and "
            "look-alike (homograph) identifiers before they reach production."
        ),
        epilog="exit codes: 0 = clean, 1 = findings present, 2 = execution error",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="files or directories to scan")
    parser.add_argument("-V", "--version", action="version", version="invisiscan " + __version__)

    parser.add_argument(
        "-f",
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--severity",
        choices=("critical", "high", "medium", "low"),
        default="low",
        help="minimum severity to report (default: low)",
    )
    parser.add_argument(
        "--rule", action="append", dest="only_rules", metavar="ID",
        help="report only this rule id (repeatable)",
    )
    parser.add_argument(
        "--ignore", action="append", dest="ignore_rules", metavar="ID",
        help="suppress this rule id (repeatable)",
    )
    parser.add_argument(
        "--no-confusables", action="store_true", help="disable IS010 homograph detection"
    )
    parser.add_argument(
        "--min-word-length", type=int, default=3, metavar="N",
        help="shortest identifier considered for confusable analysis (default: 3)",
    )
    parser.add_argument(
        "--extension", action="append", dest="extensions", metavar="EXT",
        help="file extension to include (repeatable); default: a built-in source-file set",
    )
    parser.add_argument(
        "--exclude", action="append", dest="exclude", metavar="PATTERN",
        help="skip any path containing this substring (repeatable)",
    )
    parser.add_argument("--stdin", action="store_true", help="scan stdin instead of files")
    parser.add_argument("--stdin-name", default="<stdin>", help="label used for stdin results")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress the summary footer")
    return parser


def _valid_rule_ids(ids: Optional[Sequence[str]]) -> Set[str]:
    known = {r.rule_id for r in RULES} | {"IS010", "IS011"}
    if not ids:
        return set()
    unknown = [i for i in ids if i.upper() not in known]
    if unknown:
        raise SystemExit("error: unknown rule id(s): " + ", ".join(unknown))
    return {i.upper() for i in ids}


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Must happen before any argument parsing or scanning: argparse writes its
    # own help/error text, which would crash first on a legacy codepage.
    force_utf8_stdio()

    parser = build_parser()
    args = parser.parse_args(argv)

    exclude = tuple(args.exclude or ())
    extensions: Optional[Set[str]] = None
    if args.extensions:
        extensions = {"." + e.lstrip(".").lower() for e in args.extensions}

    scanner = Scanner(
        min_severity=args.severity,
        detect_confusables=not args.no_confusables,
        min_word_length=args.min_word_length,
        allow_rules=_valid_rule_ids(args.only_rules),
        deny_rules=_valid_rule_ids(args.ignore_rules),
    )

    if args.stdin:
        data = sys.stdin.read()
        results: List[ScanResult] = [scanner.scan_text(data, args.stdin_name)]
    else:
        roots = [Path(p) for p in (args.paths or ["."])]
        missing = [p for p in roots if not p.exists()]
        if missing:
            print("error: no such path: " + ", ".join(str(p) for p in missing), file=sys.stderr)
            return EXIT_ERROR
        targets = list(iter_targets(roots, extensions, exclude))
        if not targets:
            print("no files matched the given paths and filters", file=sys.stderr)
            return EXIT_ERROR
        results = [scanner.scan_file(p) for p in targets]

    scanner.distribute_confusables(results)

    if args.format == "json":
        print(render_json(results))
    elif args.format == "sarif":
        print(render_sarif(results))
    else:
        print(render_text(results))

    dirty = any((not r.clean) for r in results)
    return EXIT_FINDINGS if dirty else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
