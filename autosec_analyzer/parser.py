from __future__ import annotations

from pathlib import Path

from .models import TraceEvent


class TraceFormatError(ValueError):
    """Raised when a trace line cannot be parsed safely."""


def parse_payload(value: str) -> tuple[int, ...]:
    tokens = value.strip().replace("0x", "").split()
    if not tokens:
        raise TraceFormatError("payload is empty")

    try:
        payload = tuple(int(token, 16) for token in tokens)
    except ValueError as exc:
        raise TraceFormatError(f"invalid hexadecimal payload: {value}") from exc

    if any(byte < 0 or byte > 0xFF for byte in payload):
        raise TraceFormatError(f"payload byte outside 00-FF: {value}")
    return payload


def parse_line(line: str, line_number: int) -> TraceEvent:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        raise TraceFormatError("skip")

    parts = [part.strip() for part in raw.split(",")]
    timestamp = parts[0]
    fields: dict[str, str] = {}

    for part in parts[1:]:
        if "=" not in part:
            raise TraceFormatError(f"line {line_number}: field lacks '=': {part}")
        key, value = part.split("=", 1)
        fields[key.strip().lower()] = value.strip()

    missing = {"module", "direction", "payload"} - fields.keys()
    if missing:
        names = ", ".join(sorted(missing))
        raise TraceFormatError(f"line {line_number}: missing fields: {names}")

    direction = fields["direction"].upper()
    if direction not in {"TX", "RX"}:
        raise TraceFormatError(f"line {line_number}: direction must be TX or RX")

    return TraceEvent(
        line_number=line_number,
        timestamp=timestamp,
        module=fields["module"].upper(),
        direction=direction,
        payload=parse_payload(fields["payload"]),
        note=fields.get("note", ""),
    )


def load_trace(path: str | Path) -> list[TraceEvent]:
    trace_path = Path(path)
    if not trace_path.exists():
        raise FileNotFoundError(trace_path)

    events: list[TraceEvent] = []
    errors: list[str] = []

    for line_number, line in enumerate(trace_path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            events.append(parse_line(line, line_number))
        except TraceFormatError as exc:
            if str(exc) != "skip":
                errors.append(str(exc))

    if errors:
        raise TraceFormatError("\n".join(errors))
    if not events:
        raise TraceFormatError("trace contains no events")
    return events
