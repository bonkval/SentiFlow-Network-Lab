from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid

def utc_now() -> str: return datetime.now(timezone.utc).isoformat()

@dataclass(slots=True)
class NetworkEvent:
    timestamp: str; source_ip: str; destination_ip: str
    source_port: int = 0; destination_port: int = 0; protocol: str = "UNKNOWN"
    bytes_sent: int = 0; bytes_received: int = 0; event_type: str = "flow"
    dns_query: str = ""; outcome: str = "unknown"; source: str = "unknown"
    simulation: bool = False; scenario_id: str = ""; label: str = "BENIGN"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    def to_dict(self) -> dict[str, Any]: return asdict(self)

@dataclass(slots=True)
class Incident:
    detection_type: str; severity: str; title: str; description: str
    source_ip: str; destination_ip: str; evidence: dict[str, Any]
    first_seen: str; last_seen: str; source: str; simulation: bool
    scenario_id: str = ""; status: str = "open"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=utc_now)
    def to_dict(self) -> dict[str, Any]: return asdict(self)
