from __future__ import annotations

import argparse
import sys

from .analyzer import analyze
from .parser import TraceFormatError, load_trace
from .reporting import export_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze a synthetic automotive UDS diagnostic trace.")
    parser.add_argument("trace", help="Path to a synthetic trace text file")
    parser.add_argument("--output", default="reports", help="Directory for generated reports")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        events = load_trace(args.trace)
        findings, states, metrics = analyze(events)
        paths = export_reports(args.output, events, findings, states, metrics)
    except (FileNotFoundError, TraceFormatError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"events: {len(events)}")
    print(f"findings: {len(findings)}")
    for name, path in paths.items():
        print(f"{name}: {path}")

    return 1 if any(finding.verdict == "FAIL" for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
