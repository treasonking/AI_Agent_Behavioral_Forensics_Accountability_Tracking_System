from typing import Dict, List, Optional, Tuple

from backend.app.models.event_types import ResponsibilityType


RISK_INSTRUCTION_KEYWORDS = [
    "secret.txt",
    ".env",
    "password.txt",
    "read file",
    "파일을 읽어",
    "읽어라",
    "send to",
    "외부로 전송",
    "upload",
    "post",
    "run command",
    "명령 실행",
    "powershell",
    "bash",
    "curl",
]
INJECTION_HINTS = [
    "ignore previous instructions",
    "이전 지시를 무시",
]


class ResponsibilityClassifier:
    """Attribute risky actions to the most plausible upstream source."""

    @staticmethod
    def _append_reason(reasons: List[str], code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    @staticmethod
    def _has_instruction(text: Optional[str]) -> bool:
        normalized = (text or "").lower()
        return any(keyword in normalized for keyword in RISK_INSTRUCTION_KEYWORDS)

    @staticmethod
    def _has_injection(text: Optional[str]) -> bool:
        normalized = (text or "").lower()
        return any(keyword in normalized for keyword in INJECTION_HINTS)

    def classify(
        self,
        source: Dict[str, object],
        user_prompt: str,
        document_content: Optional[str],
        tool_result: Optional[str],
    ) -> Tuple[str, List[str]]:
        reasons: List[str] = []

        if source.get("policy_blocked"):
            self._append_reason(reasons, "POLICY_BLOCKED")
            return ResponsibilityType.POLICY_BLOCKED.value, reasons

        if self._has_instruction(user_prompt):
            self._append_reason(reasons, "USER_DIRECTED")
            return ResponsibilityType.USER_DIRECTED.value, reasons

        if document_content and (
            self._has_instruction(document_content) or self._has_injection(document_content)
        ):
            self._append_reason(reasons, "DOCUMENT_INJECTION")
            return ResponsibilityType.DOCUMENT_INDUCED.value, reasons

        if tool_result and self._has_instruction(tool_result):
            self._append_reason(reasons, "TOOL_RESULT_CHAIN")
            return ResponsibilityType.TOOL_RESULT_INDUCED.value, reasons

        if source.get("autonomous") or source.get("triggered_by") in {None, "agent"}:
            self._append_reason(reasons, "AGENT_AUTONOMY")
            return ResponsibilityType.AGENT_INDUCED.value, reasons

        self._append_reason(reasons, "UNKNOWN_ATTRIBUTION")
        return ResponsibilityType.UNKNOWN.value, reasons
