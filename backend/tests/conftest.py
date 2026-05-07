from pathlib import Path

import pytest

from backend.app.agent.simulator import AgentSimulator
from backend.app.forensic.causal_graph import CausalGraphBuilder
from backend.app.forensic.event_logger import ForensicEventLogger
from backend.app.forensic.hash_chain import HashChainBuilder
from backend.app.forensic.responsibility_classifier import ResponsibilityClassifier
from backend.app.forensic.risk_classifier import RiskClassifier
from backend.app.reports.report_generator import IncidentReportGenerator
from backend.app.storage.event_repository import EventRepository
from backend.app.tools.command_tool import CommandTool
from backend.app.tools.file_tool import FileReadTool
from backend.app.tools.web_tool import ExternalGetTool, ExternalPostTool


@pytest.fixture
def repository(tmp_path: Path) -> EventRepository:
    return EventRepository(tmp_path / "agenttrace_test.db")


@pytest.fixture
def event_logger(repository: EventRepository) -> ForensicEventLogger:
    return ForensicEventLogger(repository=repository, hash_chain_builder=HashChainBuilder(), summary_limit=160)


@pytest.fixture
def risk_classifier() -> RiskClassifier:
    return RiskClassifier()


@pytest.fixture
def responsibility_classifier() -> ResponsibilityClassifier:
    return ResponsibilityClassifier()


@pytest.fixture
def report_generator(tmp_path: Path) -> IncidentReportGenerator:
    return IncidentReportGenerator(report_dir=tmp_path / "reports")


@pytest.fixture
def simulator(
    event_logger: ForensicEventLogger,
    risk_classifier: RiskClassifier,
    responsibility_classifier: ResponsibilityClassifier,
    report_generator: IncidentReportGenerator,
) -> AgentSimulator:
    tools = {
        "READ_FILE": FileReadTool(event_logger, risk_classifier, responsibility_classifier),
        "EXTERNAL_HTTP_POST": ExternalPostTool(event_logger, risk_classifier, responsibility_classifier),
        "EXTERNAL_HTTP_GET": ExternalGetTool(event_logger, risk_classifier, responsibility_classifier),
        "RUN_COMMAND": CommandTool(event_logger, risk_classifier, responsibility_classifier),
    }
    return AgentSimulator(
        event_logger=event_logger,
        risk_classifier=risk_classifier,
        responsibility_classifier=responsibility_classifier,
        tools=tools,
        graph_builder=CausalGraphBuilder(),
        report_generator=report_generator,
    )
