import re
from typing import Dict, List, Optional


URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
FILE_PATTERN = re.compile(
    r"(secret\.txt|report\.txt|password\.txt|\.env|env file|환경변수 파일|api key|api_key|token|토큰|credential|client_secret)",
    re.IGNORECASE,
)
COMMAND_HINTS = [
    "powershell",
    "powershell 실행",
    "bash",
    "bash로 curl",
    "curl",
    "run command",
    "shell command",
    "cmd 실행",
    "쉘 명령",
    "명령 실행",
    "실행해",
    "실행하라",
]
READ_HINTS = [
    "파일을 읽어",
    "read file",
    "읽어라",
    "읽어줘",
    "read ",
    "환경변수 파일",
    "api 키",
    "api key",
    "토큰",
    "추출해",
    "가져와",
    "열어",
    "찾아",
]
TRANSFER_HINTS = [
    "외부로 전송",
    "외부 서버로 보내",
    "send to",
    "post",
    "post로 보내",
    "upload",
    "업로드",
    "결과를 전송",
    "전송해",
    "webhook",
    "callback",
]


class AgentPlanner:
    """Create deterministic tool plans from prompts and context documents."""

    @staticmethod
    def _add_step(
        steps: List[Dict[str, Optional[str]]],
        action: str,
        target: Optional[str],
        triggered_by: str,
        reason: str,
    ) -> None:
        candidate = (action, target, triggered_by)
        existing = {(step["action"], step.get("target"), step["triggered_by"]) for step in steps}
        if candidate in existing:
            return
        steps.append(
            {
                "step": len(steps) + 1,
                "action": action,
                "target": target,
                "triggered_by": triggered_by,
                "reason": reason,
            }
        )

    @staticmethod
    def _extract_url(text: str) -> Optional[str]:
        match = URL_PATTERN.search(text or "")
        return match.group(0) if match else None

    @staticmethod
    def _extract_file(text: str) -> Optional[str]:
        lowered = (text or "").lower()
        if ".env" in lowered or "환경변수 파일" in (text or "") or "env file" in lowered:
            return ".env"
        if any(keyword in lowered for keyword in ["api key", "api_key", "api 키", "토큰", "token", "credential", "client_secret"]):
            return "secret.txt"
        match = FILE_PATTERN.search(text or "")
        return match.group(1) if match else None

    @staticmethod
    def _extract_command(text: str) -> str:
        lowered = (text or "").lower()
        for hint in ["powershell", "bash", "curl", "rm -rf", "ls", "cat"]:
            index = lowered.find(hint)
            if index >= 0:
                return text[index:].strip()
        return text.strip()

    @staticmethod
    def _contains_file_read(text: str) -> bool:
        lowered = (text or "").lower()
        has_file_name = bool(FILE_PATTERN.search(text or ""))
        has_hint = any(hint in lowered for hint in READ_HINTS)
        return has_file_name and has_hint or "secret.txt" in lowered

    @staticmethod
    def _contains_transfer(text: str) -> bool:
        lowered = (text or "").lower()
        return any(hint in lowered for hint in TRANSFER_HINTS) or (
            "http" in lowered and any(hint in lowered for hint in ["보내", "전송", "upload", "업로드", "webhook", "callback"])
        )

    @staticmethod
    def _contains_command(text: str) -> bool:
        lowered = (text or "").lower()
        return any(hint in lowered for hint in COMMAND_HINTS)

    def create_plan(self, user_prompt: str, context_documents: Optional[List[dict]] = None) -> List[dict]:
        steps: List[Dict[str, Optional[str]]] = []

        if self._contains_file_read(user_prompt):
            self._add_step(
                steps,
                action="READ_FILE",
                target=self._extract_file(user_prompt) or "secret.txt",
                triggered_by="user_prompt",
                reason="user prompt requests file access",
            )

        if self._contains_transfer(user_prompt) and "http" in user_prompt.lower():
            self._add_step(
                steps,
                action="EXTERNAL_HTTP_POST",
                target=self._extract_url(user_prompt) or "https://example.com/upload",
                triggered_by="user_prompt",
                reason="user prompt requests external transfer",
            )

        if self._contains_command(user_prompt):
            self._add_step(
                steps,
                action="RUN_COMMAND",
                target=self._extract_command(user_prompt),
                triggered_by="user_prompt",
                reason="user prompt requests command execution",
            )

        for document in context_documents or []:
            content = document.get("content", "")
            document_id = document.get("document_id", "document")

            if self._contains_file_read(content):
                self._add_step(
                    steps,
                    action="READ_FILE",
                    target=self._extract_file(content) or "secret.txt",
                    triggered_by=document_id,
                    reason="document contains instruction to read a file",
                )

            if self._contains_transfer(content):
                self._add_step(
                    steps,
                    action="EXTERNAL_HTTP_POST",
                    target=self._extract_url(content) or "https://example.com/upload",
                    triggered_by=document_id,
                    reason="document contains instruction to exfiltrate data",
                )

            if self._contains_command(content):
                self._add_step(
                    steps,
                    action="RUN_COMMAND",
                    target=self._extract_command(content),
                    triggered_by=document_id,
                    reason="document contains instruction to run a command",
                )

        if not steps:
            steps.append(
                {
                    "step": 1,
                    "action": "SAFE_SUMMARY",
                    "target": None,
                    "triggered_by": "user_prompt",
                    "reason": "no risky tool action required",
                }
            )

        for index, step in enumerate(steps, start=1):
            step["step"] = index

        return steps


def create_plan(user_prompt: str, context_documents: Optional[List[dict]] = None) -> List[dict]:
    return AgentPlanner().create_plan(user_prompt=user_prompt, context_documents=context_documents)
