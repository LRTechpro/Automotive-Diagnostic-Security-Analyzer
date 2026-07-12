# Automotive Diagnostic Security Analyzer

[![CI](https://github.com/LRTechpro/Automotive-Diagnostic-Security-Analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/LRTechpro/Automotive-Diagnostic-Security-Analyzer/actions/workflows/ci.yml)

A clean-room automotive cybersecurity portfolio project for analyzing synthetic UDS diagnostic traces, identifying security-relevant behavior, tracking diagnostic state, and exporting evidence-based findings.

This repository was created from scratch with a new Git history. It contains no OEM logs, VINs, customer records, proprietary software packages, internal URLs, or production vehicle data.

## What it demonstrates

- UDS service and negative-response decoding
- Diagnostic-session and SecurityAccess state tracking
- Negative-path and programming-sequence validation
- Security-relevant finding classification
- Reproducible Markdown, JSON, and CSV reporting
- Command-line and Tkinter desktop interfaces
- Standard-library Python with automated tests and CI

## Supported UDS patterns

- `0x10` DiagnosticSessionControl
- `0x11` ECUReset
- `0x22` ReadDataByIdentifier
- `0x27` SecurityAccess
- `0x2E` WriteDataByIdentifier
- `0x31` RoutineControl
- `0x34` RequestDownload
- `0x36` TransferData
- `0x37` RequestTransferExit
- `0x3E` TesterPresent
- `0x7F` NegativeResponse

The analyzer recognizes common NRCs including securityAccessDenied, invalidKey, exceededNumberOfAttempts, requiredTimeDelayNotExpired, requestOutOfRange, generalProgrammingFailure, wrongBlockSequenceCounter, and responsePending.

## Synthetic trace format

Each line uses comma-separated key/value fields:

```text
2026-07-12T12:00:00Z,module=BMS_SIM,direction=TX,payload=10 03,note=Enter extended session
2026-07-12T12:00:00Z,module=BMS_SIM,direction=RX,payload=50 03,note=Extended session accepted
```

Required fields:

- `module`
- `direction` with `TX` for tester request or `RX` for ECU response
- `payload` as hexadecimal bytes

All included examples are fictional and synthetic.

## Quick start

Install the package in editable mode:

```bash
python -m pip install -e .
```

Analyze the bundled synthetic trace:

```bash
python -m autosec_analyzer.cli sample_data/synthetic_diagnostic_log.txt --output reports
```

Generated outputs:

```text
reports/analysis.md
reports/analysis.json
reports/findings.csv
```

Launch the desktop interface:

```bash
python -m autosec_analyzer.gui
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Architecture

```text
autosec_analyzer/
  parser.py       Trace ingestion and validation
  uds.py          Deterministic UDS decoding
  analyzer.py     State tracking and security rules
  reporting.py    Markdown, JSON, and CSV export
  cli.py          Command-line interface
  gui.py          Tkinter desktop interface
sample_data/
  synthetic_diagnostic_log.txt
tests/
  test_analyzer.py
```

## Engineering value

The project demonstrates how diagnostic evidence can be transformed into repeatable verification findings. It focuses on protocol behavior, security preconditions, state transitions, and traceable reporting rather than presenting a simple byte decoder.

## Engineering boundaries

This project is a portfolio and learning artifact. It does not:

- reproduce any OEM diagnostic platform
- contain production diagnostic traces
- certify ISO/SAE 21434 compliance
- perform vehicle penetration testing
- communicate with a physical vehicle
- implement production cryptography or secure boot

See [SECURITY.md](SECURITY.md) for the repository data-handling policy.

## License

MIT