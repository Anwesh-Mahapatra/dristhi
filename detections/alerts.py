import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Alert:
    rule_name: str
    severity: str
    timestamp: str
    matched_event: str
    user_name: Optional[str] = None
    src_ip: Optional[str] = None

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def build(cls, rule_name, severity, source_event: dict, user_name=None, src_ip=None) -> "Alert":
        return cls(
            rule_name=rule_name,
            severity=severity,
            timestamp=cls.now_iso(),
            matched_event=json.dumps(source_event, default=str),
            user_name=user_name,
            src_ip=src_ip,
        )

    def to_dict(self) -> dict:
        return asdict(self)