from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

from backend.app.agent.simulator import AgentSimulator
from backend.app.database import DEFAULT_REPORT_DIR
from backend.app.forensic.causal_graph import CausalGraphBuilder
from backend.app.forensic.event_logger import ForensicEventLogger
from backend.app.forensic.hash_chain import HashChainBuilder
from backend.app.forensic.responsibility_classifier import ResponsibilityClassifier
from backend.app.forensic.risk_classifier import RiskClassifier
from backend.app.models.schemas import AgentRequest, AgentResponse
from backend.app.reports.report_generator import IncidentReportGenerator
from backend.app.storage.event_repository import EventRepository
from backend.app.tools.command_tool import CommandTool
from backend.app.tools.file_tool import FileReadTool
from backend.app.tools.web_tool import ExternalGetTool, ExternalPostTool


repository = EventRepository()
event_logger = ForensicEventLogger(repository=repository, hash_chain_builder=HashChainBuilder())
risk_classifier = RiskClassifier()
responsibility_classifier = ResponsibilityClassifier()
graph_builder = CausalGraphBuilder()
report_generator = IncidentReportGenerator()

tools = {
    "READ_FILE": FileReadTool(event_logger, risk_classifier, responsibility_classifier),
    "EXTERNAL_HTTP_POST": ExternalPostTool(event_logger, risk_classifier, responsibility_classifier),
    "EXTERNAL_HTTP_GET": ExternalGetTool(event_logger, risk_classifier, responsibility_classifier),
    "RUN_COMMAND": CommandTool(event_logger, risk_classifier, responsibility_classifier),
}

simulator = AgentSimulator(
    event_logger=event_logger,
    risk_classifier=risk_classifier,
    responsibility_classifier=responsibility_classifier,
    tools=tools,
    graph_builder=graph_builder,
    report_generator=report_generator,
)

app = FastAPI(title="AgentTrace", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "AgentTrace"}


@app.post("/agent/run", response_model=AgentResponse)
def run_agent(request: AgentRequest) -> AgentResponse:
    return simulator.run(request)


@app.get("/sessions/{session_id}/events")
def get_session_events(session_id: str):
    return event_logger.get_events(session_id)


@app.get("/sessions/{session_id}/verify")
def verify_session(session_id: str) -> dict:
    return {"session_id": session_id, "hash_chain_valid": event_logger.verify_session(session_id)}


@app.get("/sessions/{session_id}/graph")
def get_session_graph(session_id: str) -> dict:
    events = event_logger.get_events(session_id)
    if not events:
        raise HTTPException(status_code=404, detail="Session not found")
    return graph_builder.build_graph(events)


@app.get("/sessions/{session_id}/report", response_class=PlainTextResponse)
def get_session_report(session_id: str) -> str:
    report_path = Path(DEFAULT_REPORT_DIR) / f"incident_{session_id}.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Incident report not found")
    return report_path.read_text(encoding="utf-8")
