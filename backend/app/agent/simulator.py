from typing import Dict, List, Optional

from backend.app.agent.planner import AgentPlanner
from backend.app.forensic.causal_graph import CausalGraphBuilder
from backend.app.forensic.responsibility_classifier import ResponsibilityClassifier
from backend.app.forensic.risk_classifier import RiskClassifier
from backend.app.models.event_types import ActorType, EventType, ResponsibilityType, RiskLevel
from backend.app.models.schemas import AgentRequest, AgentResponse
from backend.app.reports.report_generator import IncidentReportGenerator


class AgentSimulator:
    """Run a deterministic agent workflow and record every significant step."""

    def __init__(
        self,
        event_logger,
        risk_classifier: RiskClassifier,
        responsibility_classifier: ResponsibilityClassifier,
        tools: Dict[str, object],
        planner: Optional[AgentPlanner] = None,
        graph_builder: Optional[CausalGraphBuilder] = None,
        report_generator: Optional[IncidentReportGenerator] = None,
    ):
        self.event_logger = event_logger
        self.risk_classifier = risk_classifier
        self.responsibility_classifier = responsibility_classifier
        self.tools = tools
        self.planner = planner or AgentPlanner()
        self.graph_builder = graph_builder or CausalGraphBuilder()
        self.report_generator = report_generator or IncidentReportGenerator()

    @staticmethod
    def _dedupe(items: List[str]) -> List[str]:
        return list(dict.fromkeys(items))

    @staticmethod
    def _policy_action(risk_level: str) -> str:
        if risk_level == RiskLevel.CRITICAL.value:
            return "BLOCK"
        if risk_level == RiskLevel.HIGH.value:
            return "WARN"
        return "ALLOW"

    def _response_text(self, action: str, highest_tool_action: Optional[str], highest_risk: str) -> str:
        if action == "BLOCK" and highest_tool_action == "EXTERNAL_HTTP_POST":
            return "외부 전송 시도가 감지되어 차단되었습니다. 사고 리포트가 생성되었습니다."
        if action == "BLOCK" and highest_tool_action == "RUN_COMMAND":
            return "명령 실행 시도가 감지되어 차단되었습니다."
        if highest_risk == RiskLevel.HIGH.value:
            return "민감 파일 접근 시도가 감지되어 작업이 제한되었습니다."
        return "요청이 안전하게 처리되었습니다."

    def run(self, request: AgentRequest) -> AgentResponse:
        session_id = self.event_logger.start_session(request.session_id)
        context_documents = request.context_documents or []
        documents_by_id = {
            document.get("document_id", f"doc-{index}"): document
            for index, document in enumerate(context_documents, start=1)
        }

        prompt_risk, prompt_reasons = self.risk_classifier.classify(
            event_type=EventType.USER_PROMPT.value,
            tool_name=None,
            target=None,
            content=request.user_prompt,
        )
        prompt_event = self.event_logger.log_event(
            session_id=session_id,
            actor=ActorType.USER.value,
            event_type=EventType.USER_PROMPT.value,
            input_summary=f"user prompt received: length={len(request.user_prompt)}",
            risk_level=prompt_risk,
            responsibility_type=ResponsibilityType.USER_DIRECTED.value,
            reason_codes=self._dedupe(prompt_reasons + ["SAFE_PROMPT"]),
            raw_input=request.user_prompt,
        )

        document_event_ids: Dict[str, str] = {}
        for document_id, document in documents_by_id.items():
            content = document.get("content", "")
            doc_risk, doc_reasons = self.risk_classifier.classify(
                event_type=EventType.DOCUMENT_CONTEXT.value,
                tool_name=None,
                target=document_id,
                content=content,
            )
            doc_resp, doc_resp_reasons = self.responsibility_classifier.classify(
                source={"triggered_by": document_id},
                user_prompt=request.user_prompt,
                document_content=content,
                tool_result=None,
            )
            document_event = self.event_logger.log_event(
                session_id=session_id,
                actor=ActorType.SYSTEM.value,
                event_type=EventType.DOCUMENT_CONTEXT.value,
                target=document_id,
                input_summary=f"context document ingested: {document_id}",
                risk_level=doc_risk,
                responsibility_type=doc_resp,
                reason_codes=self._dedupe(doc_reasons + doc_resp_reasons),
                triggered_by_event_id=prompt_event.event_id,
                raw_input=content,
            )
            document_event_ids[document_id] = document_event.event_id

        plan = self.planner.create_plan(request.user_prompt, context_documents)
        plan_source = next(
            (step["triggered_by"] for step in plan if step["triggered_by"] != "user_prompt"),
            "user_prompt",
        )
        plan_trigger_id = document_event_ids.get(plan_source, prompt_event.event_id)
        plan_risk = RiskLevel.LOW.value
        plan_reasons: List[str] = []
        for step in plan:
            step_risk, step_reasons = self.risk_classifier.classify(
                event_type=EventType.AGENT_PLAN.value,
                tool_name=step["action"] if step["action"] != "SAFE_SUMMARY" else None,
                target=step.get("target"),
                content=step["reason"],
            )
            plan_risk = self.risk_classifier.max_risk(plan_risk, step_risk)
            plan_reasons.extend(step_reasons)
        plan_resp, plan_resp_reasons = self.responsibility_classifier.classify(
            source={"triggered_by": plan_source},
            user_prompt=request.user_prompt,
            document_content=documents_by_id.get(plan_source, {}).get("content"),
            tool_result=None,
        )
        plan_event = self.event_logger.log_event(
            session_id=session_id,
            actor=ActorType.AI_AGENT.value,
            event_type=EventType.AGENT_PLAN.value,
            input_summary=f"agent generated {len(plan)} plan step(s)",
            output_summary=" -> ".join(step["action"] for step in plan),
            risk_level=plan_risk,
            responsibility_type=plan_resp,
            reason_codes=self._dedupe(plan_reasons + plan_resp_reasons),
            triggered_by_event_id=plan_trigger_id,
            raw_input=plan,
            raw_output={"actions": [step["action"] for step in plan]},
        )

        final_action = "ALLOW"
        final_risk = self.risk_classifier.max_risk(prompt_risk, plan_risk)
        highest_tool_action: Optional[str] = None
        last_trigger_event_id = plan_event.event_id
        last_tool_output: Optional[str] = None

        for step in plan:
            if step["action"] == "SAFE_SUMMARY":
                break

            tool = self.tools[step["action"]]
            source_document = documents_by_id.get(step["triggered_by"], {})
            payload = None
            if step["action"] == "EXTERNAL_HTTP_POST":
                payload = last_tool_output

            execution = tool.execute(
                session_id=session_id,
                target=step.get("target"),
                payload=payload,
                user_prompt=request.user_prompt,
                document_content=source_document.get("content"),
                tool_result=None,
                triggered_by_event_id=last_trigger_event_id,
                source={"triggered_by": step["triggered_by"]},
            )

            last_tool_output = execution.get("raw_output") or last_tool_output
            final_risk = self.risk_classifier.max_risk(final_risk, execution["risk_level"])
            policy_action = self._policy_action(execution["risk_level"])
            if policy_action in {"WARN", "BLOCK"}:
                highest_tool_action = step["action"]
            final_action = policy_action if policy_action != "ALLOW" else final_action

            policy_resp_source = {"policy_blocked": policy_action == "BLOCK", "triggered_by": step["triggered_by"]}
            policy_resp, policy_resp_reasons = self.responsibility_classifier.classify(
                source=policy_resp_source,
                user_prompt=request.user_prompt,
                document_content=source_document.get("content"),
                tool_result=None,
            )
            policy_reason_codes = self._dedupe(execution["reason_codes"] + policy_resp_reasons)
            policy_event = self.event_logger.log_event(
                session_id=session_id,
                actor=ActorType.SYSTEM.value,
                event_type=EventType.POLICY_DECISION.value,
                tool_name=step["action"],
                target=step.get("target"),
                input_summary=f"policy evaluated tool step: {step['action']}",
                output_summary=f"action={policy_action}",
                risk_level=execution["risk_level"],
                responsibility_type=policy_resp if policy_action == "BLOCK" else execution["responsibility_type"],
                reason_codes=policy_reason_codes,
                triggered_by_event_id=execution["result_event"].event_id,
                raw_input={"risk_level": execution["risk_level"], "tool": step["action"]},
                raw_output={"action": policy_action},
            )
            last_trigger_event_id = policy_event.event_id

            if policy_action == "BLOCK":
                break

        final_response_text = self._response_text(final_action, highest_tool_action, final_risk)
        final_resp_source = {"policy_blocked": final_action == "BLOCK", "triggered_by": plan_source}
        final_resp_responsibility, final_resp_reasons = self.responsibility_classifier.classify(
            source=final_resp_source,
            user_prompt=request.user_prompt,
            document_content=documents_by_id.get(plan_source, {}).get("content"),
            tool_result=None,
        )
        final_response_event = self.event_logger.log_event(
            session_id=session_id,
            actor=ActorType.AI_AGENT.value,
            event_type=EventType.FINAL_RESPONSE.value,
            input_summary="final response prepared",
            output_summary=final_response_text,
            risk_level=final_risk,
            responsibility_type=final_resp_responsibility,
            reason_codes=self._dedupe(final_resp_reasons),
            triggered_by_event_id=last_trigger_event_id,
            raw_output=final_response_text,
        )

        incident_report_path = None
        if final_action == "BLOCK" or final_risk == RiskLevel.CRITICAL.value:
            graph_before_report = self.graph_builder.build_graph(self.event_logger.get_events(session_id))
            incident_report_path = self.report_generator.generate(
                session_id=session_id,
                events=self.event_logger.get_events(session_id),
                graph=graph_before_report,
            )
            self.event_logger.log_event(
                session_id=session_id,
                actor=ActorType.SYSTEM.value,
                event_type=EventType.INCIDENT_REPORT.value,
                target=incident_report_path,
                output_summary=f"incident report generated: {incident_report_path}",
                risk_level=final_risk,
                responsibility_type=ResponsibilityType.POLICY_BLOCKED.value,
                reason_codes=["POLICY_BLOCKED"],
                triggered_by_event_id=final_response_event.event_id,
                raw_output=incident_report_path,
            )

        events = self.event_logger.get_events(session_id)
        graph = self.graph_builder.build_graph(events)

        return AgentResponse(
            session_id=session_id,
            final_response=final_response_text,
            action=final_action,
            risk_level=final_risk,
            events=events,
            incident_report_path=incident_report_path,
            graph=graph,
        )
