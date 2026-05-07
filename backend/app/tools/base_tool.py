from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from backend.app.forensic.responsibility_classifier import ResponsibilityClassifier
from backend.app.forensic.risk_classifier import RiskClassifier
from backend.app.models.event_types import ActorType, EventType


class BaseTool(ABC):
    """Shared wrapper that logs tool calls and results around mock execution."""

    name = "NONE"

    def __init__(self, event_logger, risk_classifier: RiskClassifier, responsibility_classifier: ResponsibilityClassifier):
        self.event_logger = event_logger
        self.risk_classifier = risk_classifier
        self.responsibility_classifier = responsibility_classifier

    def summarize_input(self, target: Optional[str], payload: Optional[Any] = None) -> str:
        if target:
            return f"tool input target: {target}"
        return f"tool input payload: {str(payload)[:80]}"

    def summarize_output(self, result: Dict[str, Any]) -> str:
        return str(result.get("public_summary") or result.get("status") or "tool execution complete")

    @abstractmethod
    def run(self, target: Optional[str], payload: Optional[Any] = None) -> Dict[str, Any]:
        raise NotImplementedError

    def execute(
        self,
        session_id: str,
        *,
        target: Optional[str],
        payload: Optional[Any],
        user_prompt: str,
        document_content: Optional[str],
        tool_result: Optional[str],
        triggered_by_event_id: Optional[str],
        source: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        source = source or {"triggered_by": "agent", "autonomous": True}

        responsibility_type, responsibility_reasons = self.responsibility_classifier.classify(
            source=source,
            user_prompt=user_prompt,
            document_content=document_content,
            tool_result=tool_result,
        )

        input_summary = self.summarize_input(target=target, payload=payload)
        call_risk, call_reasons = self.risk_classifier.classify(
            event_type=EventType.TOOL_CALL.value,
            tool_name=self.name,
            target=target,
            content=str(payload if payload is not None else target or ""),
        )
        call_reason_codes = list(dict.fromkeys(call_reasons + responsibility_reasons))
        call_event = self.event_logger.log_event(
            session_id=session_id,
            actor=ActorType.TOOL.value,
            event_type=EventType.TOOL_CALL.value,
            tool_name=self.name,
            target=target,
            input_summary=input_summary,
            output_summary=None,
            risk_level=call_risk,
            responsibility_type=responsibility_type,
            reason_codes=call_reason_codes,
            triggered_by_event_id=triggered_by_event_id,
            raw_input=payload if payload is not None else target,
        )

        result = self.run(target=target, payload=payload)
        output_summary = self.summarize_output(result)
        output_value = result.get("raw_output")
        result_risk, result_reasons = self.risk_classifier.classify(
            event_type=EventType.TOOL_RESULT.value,
            tool_name=self.name,
            target=target,
            content=str(output_value if output_value is not None else output_summary),
        )
        combined_risk = self.risk_classifier.max_risk(call_risk, result_risk)
        result_reason_codes = list(
            dict.fromkeys(call_reasons + result_reasons + responsibility_reasons + result.get("reason_codes", []))
        )
        result_event = self.event_logger.log_event(
            session_id=session_id,
            actor=ActorType.TOOL.value,
            event_type=EventType.TOOL_RESULT.value,
            tool_name=self.name,
            target=target,
            input_summary=None,
            output_summary=output_summary,
            risk_level=combined_risk,
            responsibility_type=responsibility_type,
            reason_codes=result_reason_codes,
            triggered_by_event_id=call_event.event_id,
            raw_output=output_value,
        )

        return {
            "call_event": call_event,
            "result_event": result_event,
            "risk_level": combined_risk,
            "reason_codes": result_reason_codes,
            "responsibility_type": responsibility_type,
            "raw_output": output_value,
            "public_output": output_summary,
            "status": result.get("status", "success"),
            "blocked": result.get("blocked", False),
        }
