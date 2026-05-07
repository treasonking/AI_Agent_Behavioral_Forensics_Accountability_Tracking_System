from typing import Any, Dict, Optional

from backend.app.models.event_types import ToolName
from backend.app.tools.base_tool import BaseTool


DEFAULT_MOCK_FILES = {
    "report.txt": "일반 보고서 내용입니다.",
    "secret.txt": "API_KEY=sk-test-secret-value",
    ".env": "OPENAI_API_KEY=secret",
}


class FileReadTool(BaseTool):
    name = ToolName.READ_FILE.value

    def __init__(self, event_logger, risk_classifier, responsibility_classifier, mock_files: Optional[Dict[str, str]] = None):
        super().__init__(event_logger, risk_classifier, responsibility_classifier)
        self.mock_files = mock_files or DEFAULT_MOCK_FILES

    def summarize_input(self, target: Optional[str], payload: Optional[Any] = None) -> str:
        return f"read file request: {target}"

    def summarize_output(self, result: Dict[str, Any]) -> str:
        return result["public_summary"]

    def run(self, target: Optional[str], payload: Optional[Any] = None) -> Dict[str, Any]:
        content = self.mock_files.get(target or "", "")
        if target in self.mock_files:
            return {
                "status": "success",
                "public_summary": f"file read success: {target}",
                "raw_output": content,
            }
        return {
            "status": "not_found",
            "public_summary": f"file read failed: {target}",
            "raw_output": "",
            "reason_codes": ["FILE_NOT_FOUND"],
        }
