from __future__ import annotations

from dataclasses import dataclass


SERVICES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x22: "ReadDataByIdentifier",
    0x27: "SecurityAccess",
    0x2E: "WriteDataByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x3E: "TesterPresent",
}

NRCS = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "responsePending",
}

SESSION_NAMES = {
    0x01: "default",
    0x02: "programming",
    0x03: "extended",
}


@dataclass(frozen=True)
class DecodedUds:
    kind: str
    service_id: int | None
    service_name: str
    subfunction: int | None = None
    nrc: int | None = None
    nrc_name: str = ""


def decode(payload: tuple[int, ...]) -> DecodedUds:
    if not payload:
        return DecodedUds("unknown", None, "empty")

    sid = payload[0]
    if sid == 0x7F and len(payload) >= 3:
        rejected_sid = payload[1]
        nrc = payload[2]
        return DecodedUds(
            kind="negative_response",
            service_id=rejected_sid,
            service_name=SERVICES.get(rejected_sid, f"Service0x{rejected_sid:02X}"),
            nrc=nrc,
            nrc_name=NRCS.get(nrc, f"NRC0x{nrc:02X}"),
        )

    if sid >= 0x40:
        request_sid = sid - 0x40
        return DecodedUds(
            kind="positive_response",
            service_id=request_sid,
            service_name=SERVICES.get(request_sid, f"Service0x{request_sid:02X}"),
            subfunction=payload[1] if len(payload) > 1 else None,
        )

    return DecodedUds(
        kind="request",
        service_id=sid,
        service_name=SERVICES.get(sid, f"Service0x{sid:02X}"),
        subfunction=payload[1] if len(payload) > 1 else None,
    )
