from __future__ import annotations

from collections import Counter
from dataclasses import replace
from typing import Iterable

from .models import Finding, ModuleState, TraceEvent
from .uds import SESSION_NAMES, decode

SECURITY_NRCS = {0x33, 0x35, 0x36, 0x37}
PROGRAMMING_SERVICES = {0x2E, 0x34, 0x36, 0x37}


def analyze(events: Iterable[TraceEvent]) -> tuple[list[Finding], dict[str, ModuleState], dict[str, int]]:
    states: dict[str, ModuleState] = {}
    findings: list[Finding] = []
    metrics: Counter[str] = Counter()

    for event in events:
        state = states.setdefault(event.module, ModuleState())
        decoded = decode(event.payload)
        metrics["events"] += 1
        metrics[f"direction_{event.direction.lower()}"] += 1
        metrics[f"kind_{decoded.kind}"] += 1

        if decoded.service_id is not None:
            metrics[f"service_0x{decoded.service_id:02X}"] += 1

        if event.direction == "TX" and decoded.kind == "request":
            findings.extend(_evaluate_request(event, state, decoded.service_id, decoded.subfunction))

        if event.direction == "RX":
            state, response_findings = _evaluate_response(event, state)
            states[event.module] = state
            findings.extend(response_findings)

    metrics.update(Counter(f"verdict_{finding.verdict.lower()}" for finding in findings))
    metrics.update(Counter(f"category_{finding.category}" for finding in findings))
    return findings, states, dict(sorted(metrics.items()))


def _evaluate_request(
    event: TraceEvent,
    state: ModuleState,
    service_id: int | None,
    subfunction: int | None,
) -> list[Finding]:
    if service_id is None:
        return []

    findings: list[Finding] = []

    if service_id == 0x27:
        action = "seed request" if subfunction and subfunction % 2 == 1 else "key submission"
        findings.append(_finding(event, "INFO", "security", "SecurityAccess activity", action))

    if service_id in PROGRAMMING_SERVICES and not state.security_unlocked:
        findings.append(
            _finding(
                event,
                "FAIL",
                "security",
                "Security precondition not met",
                f"0x{service_id:02X} was requested while the module state was locked.",
            )
        )

    if service_id == 0x34 and state.session != "programming":
        findings.append(
            _finding(
                event,
                "FAIL",
                "sequence",
                "Programming session precondition not met",
                f"RequestDownload was issued from the {state.session} session.",
            )
        )

    return findings


def _evaluate_response(event: TraceEvent, state: ModuleState) -> tuple[ModuleState, list[Finding]]:
    decoded = decode(event.payload)
    findings: list[Finding] = []

    if decoded.kind == "negative_response":
        verdict = "INFO" if decoded.nrc == 0x78 else "FAIL"
        category = "security" if decoded.nrc in SECURITY_NRCS else "protocol"
        findings.append(
            _finding(
                event,
                verdict,
                category,
                f"Negative response: {decoded.nrc_name}",
                f"{decoded.service_name} returned NRC 0x{decoded.nrc:02X} ({decoded.nrc_name}).",
            )
        )
        return state, findings

    if decoded.kind != "positive_response" or decoded.service_id is None:
        return state, findings

    if decoded.service_id == 0x10 and decoded.subfunction is not None:
        session = SESSION_NAMES.get(decoded.subfunction & 0x7F, f"session_0x{decoded.subfunction:02X}")
        state = replace(state, session=session, security_unlocked=False)
        findings.append(_finding(event, "PASS", "state", "Diagnostic session changed", session))

    elif decoded.service_id == 0x27 and decoded.subfunction is not None:
        if decoded.subfunction % 2 == 0:
            state = replace(state, security_unlocked=True)
            findings.append(_finding(event, "PASS", "security", "SecurityAccess granted", "Module state is unlocked."))
        else:
            findings.append(_finding(event, "INFO", "security", "Security seed received", "Challenge data returned."))

    elif decoded.service_id in PROGRAMMING_SERVICES:
        findings.append(
            _finding(
                event,
                "PASS",
                "programming",
                f"{decoded.service_name} accepted",
                "Positive response observed.",
            )
        )

    return state, findings


def _finding(
    event: TraceEvent,
    verdict: str,
    category: str,
    title: str,
    detail: str,
) -> Finding:
    return Finding(
        line_number=event.line_number,
        module=event.module,
        verdict=verdict,
        category=category,
        title=title,
        detail=detail,
        payload_hex=event.payload_hex,
    )
