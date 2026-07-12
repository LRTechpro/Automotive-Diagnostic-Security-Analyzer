from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from .models import Finding, ModuleState, TraceEvent


def export_reports(
    output_dir: str | Path,
    events: list[TraceEvent],
    findings: list[Finding],
    states: dict[str, ModuleState],
    metrics: dict[str, int],
) -> dict[str, Path]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    paths = {
        "markdown": destination / "analysis.md",
        "json": destination / "analysis.json",
        "csv": destination / "findings.csv",
    }

    paths["markdown"].write_text(_markdown(events, findings, states, metrics), encoding="utf-8")
    paths["json"].write_text(
        json.dumps(
            {
                "events": [event.to_dict() for event in events],
                "findings": [finding.to_dict() for finding in findings],
                "module_states": {
                    module: {
                        "session": state.session,
                        "security_unlocked": state.security_unlocked,
                    }
                    for module, state in states.items()
                },
                "metrics": metrics,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    with paths["csv"].open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["line_number", "module", "verdict", "category", "title", "detail", "payload_hex"],
        )
        writer.writeheader()
        writer.writerows(finding.to_dict() for finding in findings)

    return paths


def _markdown(
    events: list[TraceEvent],
    findings: list[Finding],
    states: dict[str, ModuleState],
    metrics: dict[str, int],
) -> str:
    counts = Counter(finding.verdict for finding in findings)
    lines = [
        "# Automotive Diagnostic Security Analysis",
        "",
        "> Data boundary: This report was generated from a synthetic portfolio trace.",
        "",
        "## Summary",
        "",
        f"- Events: {len(events)}",
        f"- PASS: {counts.get('PASS', 0)}",
        f"- FAIL: {counts.get('FAIL', 0)}",
        f"- INFO: {counts.get('INFO', 0)}",
        "",
        "## Findings",
        "",
        "| Line | Module | Verdict | Category | Finding | Detail | Payload |",
        "|---:|---|---|---|---|---|---|",
    ]

    for finding in findings:
        detail = finding.detail.replace("|", "\\|")
        lines.append(
            f"| {finding.line_number} | {finding.module} | {finding.verdict} | "
            f"{finding.category} | {finding.title} | {detail} | `{finding.payload_hex}` |"
        )

    lines.extend(["", "## Final module state", ""])
    for module, state in sorted(states.items()):
        lines.append(
            f"- **{module}**: session={state.session}, security_unlocked={str(state.security_unlocked).lower()}"
        )

    lines.extend(["", "## Metrics", ""])
    for key, value in metrics.items():
        lines.append(f"- `{key}`: {value}")

    lines.append("")
    return "\n".join(lines)
