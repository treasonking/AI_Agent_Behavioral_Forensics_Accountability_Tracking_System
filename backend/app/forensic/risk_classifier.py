from typing import List, Optional, Tuple

from backend.app.models.event_types import EventType, RiskLevel, ToolName


RISK_ORDER = {
    RiskLevel.LOW.value: 0,
    RiskLevel.MEDIUM.value: 1,
    RiskLevel.HIGH.value: 2,
    RiskLevel.CRITICAL.value: 3,
}

SENSITIVE_KEYWORDS = [
    "secret",
    "password",
    "token",
    "credential",
    "private",
    ".env",
    "api_key",
    "openai_api_key",
    "주민번호",
    "개인정보",
    "key",
]
INJECTION_KEYWORDS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "이전 지시를 무시",
    "시스템 프롬프트",
    "system prompt",
]
EXFILTRATION_KEYWORDS = [
    "send to",
    "external transfer",
    "exfiltrate",
    "upload",
    "외부로 전송",
    "post",
]
DANGEROUS_COMMAND_KEYWORDS = [
    "rm",
    "del",
    "format",
    "curl",
    "powershell",
    "bash",
    "chmod",
    "sudo",
]


class RiskClassifier:
    """Classify forensic event risk levels and supporting reason codes."""

    @staticmethod
    def max_risk(*levels: str) -> str:
        valid = [level for level in levels if level]
        if not valid:
            return RiskLevel.LOW.value
        return max(valid, key=lambda item: RISK_ORDER.get(item, 0))

    @staticmethod
    def _append_reason(reasons: List[str], code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    def classify(
        self,
        event_type: str,
        tool_name: Optional[str],
        target: Optional[str],
        content: Optional[str],
    ) -> Tuple[str, List[str]]:
        normalized_target = (target or "").lower()
        normalized_content = (content or "").lower()
        combined = " ".join(part for part in [normalized_target, normalized_content] if part)

        risk = RiskLevel.LOW.value
        reasons: List[str] = []

        if event_type == EventType.USER_PROMPT.value:
            self._append_reason(reasons, "SAFE_PROMPT")
        elif event_type == EventType.FINAL_RESPONSE.value:
            self._append_reason(reasons, "SAFE_PROMPT")

        if tool_name == ToolName.READ_FILE.value:
            risk = self.max_risk(risk, RiskLevel.MEDIUM.value)
            self._append_reason(reasons, "FILE_READ")

        if tool_name == ToolName.EXTERNAL_HTTP_GET.value:
            risk = self.max_risk(risk, RiskLevel.MEDIUM.value)

        if tool_name == ToolName.RUN_COMMAND.value:
            risk = self.max_risk(risk, RiskLevel.HIGH.value)
            self._append_reason(reasons, "COMMAND_EXECUTION")

        if tool_name == ToolName.EXTERNAL_HTTP_POST.value:
            risk = self.max_risk(risk, RiskLevel.CRITICAL.value)
            self._append_reason(reasons, "EXTERNAL_TRANSFER")

        if any(keyword in combined for keyword in SENSITIVE_KEYWORDS):
            risk = self.max_risk(risk, RiskLevel.HIGH.value)
            self._append_reason(reasons, "SENSITIVE_FILE_ACCESS")

        if any(keyword in normalized_content for keyword in INJECTION_KEYWORDS):
            risk = self.max_risk(risk, RiskLevel.HIGH.value)
            self._append_reason(reasons, "PROMPT_INJECTION_ATTEMPT")
            self._append_reason(reasons, "DOCUMENT_INJECTION")

        if tool_name == ToolName.EXTERNAL_HTTP_POST.value and any(
            keyword in combined for keyword in SENSITIVE_KEYWORDS
        ):
            risk = self.max_risk(risk, RiskLevel.CRITICAL.value)
            self._append_reason(reasons, "SENSITIVE_FILE_ACCESS")
            self._append_reason(reasons, "EXTERNAL_TRANSFER")

        if tool_name == ToolName.RUN_COMMAND.value and any(
            keyword in normalized_content for keyword in DANGEROUS_COMMAND_KEYWORDS
        ):
            risk = self.max_risk(risk, RiskLevel.CRITICAL.value)
            self._append_reason(reasons, "DANGEROUS_COMMAND")

        if any(keyword in normalized_content for keyword in EXFILTRATION_KEYWORDS):
            self._append_reason(reasons, "EXTERNAL_TRANSFER")
            if tool_name == ToolName.EXTERNAL_HTTP_POST.value:
                risk = self.max_risk(risk, RiskLevel.CRITICAL.value)

        return risk, reasons
