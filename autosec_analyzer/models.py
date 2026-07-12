from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class TraceEvent:
    line_number: int
    timestamp: str
    module: str
    direction: str
    payload: tuple[int, ...]
    note: str = ""

    @property
    def payload_hex(self) -> str:
        return " ".join(f"{byte:02X}" for byte in self.payload)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["payload"] = list(self.payload)
        data["payload_hex"] = self.payload_hex
        return data


@dataclass(frozen=True)
class Finding:
    line_number: int
    module: str
    verdict: str
    category: str
    title: str
    detail: str
    payload_hex: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ModuleState:
    session: str = "default"
    security_unlocked: bool = False
