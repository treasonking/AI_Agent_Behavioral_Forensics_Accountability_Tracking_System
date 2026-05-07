from typing import Any, Dict, Optional

from backend.app.models.event_types import ToolName
from backend.app.tools.base_tool import BaseTool


class CommandTool(BaseTool):
    name = ToolName.RUN_COMMAND.value

    def summarize_input(self, target: Optional[str], payload: Optional[Any] = None) -> str:
        command = target or str(payload or "")
        return f"command execution requested: {command[:100]}"

    def summarize_output(self, result: Dict[str, Any]) -> str:
        return result["public_summary"]

    def run(self, target: Optional[str], payload: Optional[Any] = None) -> Dict[str, Any]:
        command = target or str(payload or "")
        return {
            "status": "blocked",
            "public_summary": f"command execution blocked: {command[:80]}",
            "raw_output": f"command execution blocked: {command}",
            "blocked": True,
        }
