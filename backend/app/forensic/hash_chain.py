from typing import Any, Dict, List, Optional

from backend.app.forensic.hash_utils import sha256_json


def _event_to_dict(event: Any) -> Dict[str, Any]:
    if hasattr(event, "model_dump"):
        return event.model_dump()
    if hasattr(event, "dict"):
        return event.dict()
    return dict(event)


class HashChainBuilder:
    """Build and verify event hashes linked by previous-event pointers."""

    def build_event_hash(
        self,
        event_payload: Dict[str, Any],
        previous_event_hash: Optional[str],
    ) -> str:
        payload = dict(event_payload)
        payload.pop("event_hash", None)
        payload["previous_event_hash"] = previous_event_hash
        return sha256_json(payload)

    def verify_chain(self, events: List[Any]) -> bool:
        previous_hash = None

        for event in events:
            payload = _event_to_dict(event)

            if payload.get("previous_event_hash") != previous_hash:
                return False

            expected_hash = self.build_event_hash(payload, previous_hash)
            if payload.get("event_hash") != expected_hash:
                return False

            previous_hash = payload.get("event_hash")

        return True
