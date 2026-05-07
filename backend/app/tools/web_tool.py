from typing import Any, Dict, Optional

from backend.app.models.event_types import ToolName
from backend.app.tools.base_tool import BaseTool


class ExternalPostTool(BaseTool):
    name = ToolName.EXTERNAL_HTTP_POST.value

    def summarize_input(self, target: Optional[str], payload: Optional[Any] = None) -> str:
        return f"external POST request prepared for: {target}"

    def summarize_output(self, result: Dict[str, Any]) -> str:
        return result["public_summary"]

    def run(self, target: Optional[str], payload: Optional[Any] = None) -> Dict[str, Any]:
        return {
            "status": "blocked",
            "public_summary": f"attempted external POST to {target}",
            "raw_output": f"attempted external POST to {target}",
            "blocked": True,
        }


class ExternalGetTool(BaseTool):
    name = ToolName.EXTERNAL_HTTP_GET.value

    def summarize_input(self, target: Optional[str], payload: Optional[Any] = None) -> str:
        return f"external GET request prepared for: {target}"

    def summarize_output(self, result: Dict[str, Any]) -> str:
        return result["public_summary"]

    def run(self, target: Optional[str], payload: Optional[Any] = None) -> Dict[str, Any]:
        return {
            "status": "success",
            "public_summary": f"attempted external GET to {target}",
            "raw_output": f"attempted external GET to {target}",
        }
