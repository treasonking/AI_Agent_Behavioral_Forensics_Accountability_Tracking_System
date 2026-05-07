from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from backend.app.forensic.hash_chain import HashChainBuilder
from backend.app.forensic.hash_utils import sha256_json, sha256_text
from backend.app.models.schemas import ForensicEvent
from backend.app.storage.event_repository import EventRepository


def _serialize_model(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return value


class ForensicEventLogger:
    """Create, chain, and persist forensic events per session."""

    def __init__(
        self,
        repository: Optional[EventRepository] = None,
        hash_chain_builder: Optional[HashChainBuilder] = None,
        summary_limit: int = 160,
    ):
        self.repository = repository or EventRepository()
        self.hash_chain_builder = hash_chain_builder or HashChainBuilder()
        self.summary_limit = summary_limit
        self._session_counters: Dict[str, int] = {}

    def start_session(self, session_id: Optional[str]) -> str:
        active_session_id = session_id or f"sess-{uuid4().hex[:12]}"
        self._session_counters[active_session_id] = 0
        self.repository.reset_session(active_session_id)
        return active_session_id

    def _next_event_id(self, session_id: str) -> str:
        self._session_counters[session_id] = self._session_counters.get(session_id, 0) + 1
        return f"evt-{self._session_counters[session_id]:04d}"

    def _truncate(self, text: Optional[str]) -> Optional[str]:
        if text is None:
            return None
        clean = " ".join(str(text).split())
        if len(clean) <= self.summary_limit:
            return clean
        return f"{clean[: self.summary_limit - 3]}..."

    def _hash_data(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        serialized = _serialize_model(value)
        if isinstance(serialized, str):
            return sha256_text(serialized)
        return sha256_json(serialized)

    def log_event(
        self,
        session_id: str,
        actor: str,
        event_type: str,
        tool_name: Optional[str] = None,
        target: Optional[str] = None,
        input_summary: Optional[str] = None,
        output_summary: Optional[str] = None,
        risk_level: str = "LOW",
        responsibility_type: str = "UNKNOWN",
        reason_codes: Optional[List[str]] = None,
        triggered_by_event_id: Optional[str] = None,
        raw_input: Any = None,
        raw_output: Any = None,
    ) -> ForensicEvent:
        previous_events = self.get_events(session_id)
        previous_event_hash = previous_events[-1].event_hash if previous_events else None

        event_payload = {
            "event_id": self._next_event_id(session_id),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "event_type": event_type,
            "tool_name": tool_name,
            "target": target,
            "input_summary": self._truncate(input_summary),
            "output_summary": self._truncate(output_summary),
            "risk_level": risk_level,
            "responsibility_type": responsibility_type,
            "reason_codes": list(dict.fromkeys(reason_codes or [])),
            "triggered_by_event_id": triggered_by_event_id,
            "input_hash": self._hash_data(raw_input if raw_input is not None else input_summary),
            "output_hash": self._hash_data(raw_output if raw_output is not None else output_summary),
            "previous_event_hash": previous_event_hash,
        }
        event_hash = self.hash_chain_builder.build_event_hash(event_payload, previous_event_hash)
        event = ForensicEvent(**event_payload, event_hash=event_hash)
        self.repository.save_event(event)
        return event

    def get_events(self, session_id: str) -> List[ForensicEvent]:
        return self.repository.get_events(session_id)

    def verify_session(self, session_id: str) -> bool:
        return self.hash_chain_builder.verify_chain(self.get_events(session_id))
