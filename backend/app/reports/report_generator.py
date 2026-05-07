from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
from uuid import uuid4

from backend.app.database import DEFAULT_REPORT_DIR, ensure_directory
from backend.app.forensic.hash_chain import HashChainBuilder
from backend.app.models.schemas import ForensicEvent


class IncidentReportGenerator:
    """Generate markdown incident reports without storing raw sensitive data."""

    def __init__(self, report_dir: str | Path = DEFAULT_REPORT_DIR):
        self.report_dir = ensure_directory(Path(report_dir))
        self.hash_chain_builder = HashChainBuilder()

    @staticmethod
    def _final_action(events: List[ForensicEvent]) -> str:
        for event in reversed(events):
            if event.event_type == "POLICY_DECISION" and event.output_summary:
                summary = event.output_summary.upper()
                if "BLOCK" in summary:
                    return "BLOCK"
                if "WARN" in summary:
                    return "WARN"
        return "ALLOW"

    @staticmethod
    def _final_risk(events: List[ForensicEvent]) -> str:
        priority = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return max((event.risk_level for event in events), key=lambda item: priority.get(item, 0), default="LOW")

    @staticmethod
    def _analysis(events: List[ForensicEvent], graph: Dict, integrity_valid: bool) -> List[str]:
        critical_events = [event for event in events if event.risk_level == "CRITICAL"]
        high_events = [event for event in events if event.risk_level == "HIGH"]
        root_cause = graph.get("root_cause_event_id") or "unknown"
        findings: List[str] = []

        if critical_events:
            findings.append(
                f"CRITICAL 이벤트 {len(critical_events)}건이 감지되었고, 외부 전송 또는 명령 실행과 같은 차단 대상 행동이 포함되었습니다."
            )
        elif high_events:
            findings.append(
                f"HIGH 이벤트 {len(high_events)}건이 감지되었으며, 민감 파일 접근과 같은 경고 대상 행동이 확인되었습니다."
            )
        else:
            findings.append("위험도 HIGH 이상 이벤트는 감지되지 않았습니다.")

        findings.append(f"루트 원인 후보 이벤트는 `{root_cause}` 입니다.")

        tools_used = [event.tool_name for event in events if event.tool_name]
        if tools_used:
            findings.append(f"호출된 도구는 {', '.join(dict.fromkeys(tools_used))} 입니다.")

        findings.append(
            "정책 차단 여부는 POLICY_DECISION 이벤트를 기준으로 판단되며, CRITICAL 행동은 BLOCK으로 기록됩니다."
        )
        findings.append(f"로그 무결성 검증 결과는 `{integrity_valid}` 입니다.")
        return findings

    def generate(self, session_id: str, events: List[ForensicEvent], graph: Dict) -> str:
        ensure_directory(self.report_dir)
        incident_id = f"incident-{uuid4().hex[:12]}"
        report_path = self.report_dir / f"incident_{session_id}.md"
        integrity_valid = self.hash_chain_builder.verify_chain(events)
        final_risk = self._final_risk(events)
        final_action = self._final_action(events)
        root_cause = graph.get("root_cause_event_id") or "unknown"
        generated_at = datetime.now(timezone.utc).isoformat()

        timeline_rows = []
        for event in events:
            timeline_rows.append(
                f"| {event.timestamp} | {event.actor} | {event.event_type} | "
                f"{event.tool_name or '-'} | {event.target or '-'} | {event.risk_level} | "
                f"{event.responsibility_type} |"
            )

        evidence_rows = []
        for event in events:
            evidence_rows.append(
                f"| {event.event_id} | {event.input_hash or '-'} | {event.output_hash or '-'} | "
                f"{event.event_hash} | {event.previous_event_hash or '-'} |"
            )

        reason_rows = []
        for event in events:
            reason_rows.append(f"| {event.event_id} | {', '.join(event.reason_codes) or '-'} |")

        analysis_lines = "\n".join(f"- {item}" for item in self._analysis(events, graph, integrity_valid))

        content = "\n".join(
            [
                "# AI Agent Incident Report",
                "",
                "## 1. Incident Summary",
                f"- Incident ID: {incident_id}",
                f"- Session ID: {session_id}",
                f"- Generated At: {generated_at}",
                f"- Final Risk Level: {final_risk}",
                f"- Final Action: {final_action}",
                f"- Root Cause: {root_cause}",
                "",
                "## 2. Timeline",
                "",
                "| Time | Actor | Event Type | Tool | Target | Risk | Responsibility |",
                "|---|---|---|---|---|---|---|",
                *timeline_rows,
                "",
                "## 3. Causal Chain",
                "",
                "User Prompt -> Agent Plan -> Tool Call -> Tool Result -> Policy Decision -> Final Response",
                "",
                "## 4. Evidence Hashes",
                "",
                "| Event ID | Input Hash | Output Hash | Event Hash | Previous Event Hash |",
                "|---|---|---|---|---|",
                *evidence_rows,
                "",
                "## 5. Reason Codes",
                "",
                "| Event ID | Reason Codes |",
                "|---|---|",
                *reason_rows,
                "",
                "## 6. Analysis",
                "",
                analysis_lines,
                "",
                "## 7. Graph Summary",
                "",
                f"- Nodes: {len(graph.get('nodes', []))}",
                f"- Edges: {len(graph.get('edges', []))}",
                f"- Root Cause Event: {root_cause}",
            ]
        )

        report_path.write_text(content, encoding="utf-8")
        return str(report_path)
