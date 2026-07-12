from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from autosec_analyzer.analyzer import analyze
from autosec_analyzer.parser import TraceFormatError, parse_line, parse_payload
from autosec_analyzer.reporting import export_reports
from autosec_analyzer.uds import decode


class ParserTests(unittest.TestCase):
    def test_parse_payload(self) -> None:
        self.assertEqual(parse_payload("7F 22 31"), (0x7F, 0x22, 0x31))

    def test_invalid_payload(self) -> None:
        with self.assertRaises(TraceFormatError):
            parse_payload("ZZ")

    def test_parse_line(self) -> None:
        event = parse_line(
            "2026-01-01T00:00:00Z,module=ECU_SIM,direction=TX,payload=10 03,note=test",
            1,
        )
        self.assertEqual(event.module, "ECU_SIM")
        self.assertEqual(event.direction, "TX")
        self.assertEqual(event.payload_hex, "10 03")


class UdsTests(unittest.TestCase):
    def test_negative_response(self) -> None:
        decoded = decode((0x7F, 0x27, 0x35))
        self.assertEqual(decoded.kind, "negative_response")
        self.assertEqual(decoded.nrc_name, "invalidKey")

    def test_positive_response(self) -> None:
        decoded = decode((0x67, 0x02))
        self.assertEqual(decoded.service_id, 0x27)
        self.assertEqual(decoded.subfunction, 0x02)


class AnalyzerTests(unittest.TestCase):
    def _event(self, line: int, direction: str, payload: str):
        return parse_line(
            f"2026-01-01T00:00:00Z,module=BMS_SIM,direction={direction},payload={payload},note=test",
            line,
        )

    def test_programming_before_unlock_fails(self) -> None:
        events = [
            self._event(1, "TX", "10 02"),
            self._event(2, "RX", "50 02"),
            self._event(3, "TX", "34 00"),
        ]
        findings, _, _ = analyze(events)
        titles = {finding.title for finding in findings if finding.verdict == "FAIL"}
        self.assertIn("Security precondition not met", titles)

    def test_unlock_updates_state(self) -> None:
        events = [
            self._event(1, "TX", "27 01"),
            self._event(2, "RX", "67 01 12 34"),
            self._event(3, "TX", "27 02 AB CD"),
            self._event(4, "RX", "67 02"),
        ]
        _, states, _ = analyze(events)
        self.assertTrue(states["BMS_SIM"].security_unlocked)

    def test_security_nrc_classification(self) -> None:
        findings, _, _ = analyze([self._event(1, "RX", "7F 27 35")])
        self.assertEqual(findings[0].category, "security")
        self.assertEqual(findings[0].verdict, "FAIL")

    def test_response_pending_is_info(self) -> None:
        findings, _, _ = analyze([self._event(1, "RX", "7F 31 78")])
        self.assertEqual(findings[0].verdict, "INFO")

    def test_exports(self) -> None:
        events = [self._event(1, "RX", "7F 27 35")]
        findings, states, metrics = analyze(events)
        with tempfile.TemporaryDirectory() as tmp:
            paths = export_reports(tmp, events, findings, states, metrics)
            self.assertTrue(all(path.exists() for path in paths.values()))
            self.assertIn("synthetic portfolio trace", paths["markdown"].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
