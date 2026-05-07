from copy import deepcopy

from backend.app.forensic.event_logger import ForensicEventLogger
from backend.app.forensic.hash_chain import HashChainBuilder


def _to_dict(event):
    if hasattr(event, "model_dump"):
        return event.model_dump()
    return event.dict()


def _build_events(event_logger: ForensicEventLogger):
    session_id = event_logger.start_session("sess-chain-test")
    event_logger.log_event(
        session_id=session_id,
        actor="USER",
        event_type="USER_PROMPT",
        input_summary="user prompt",
        risk_level="LOW",
        responsibility_type="USER_DIRECTED",
        reason_codes=["SAFE_PROMPT"],
        raw_input="Summarize this document",
    )
    event_logger.log_event(
        session_id=session_id,
        actor="AI_AGENT",
        event_type="AGENT_PLAN",
        target="report.txt",
        output_summary="READ_FILE",
        risk_level="MEDIUM",
        responsibility_type="USER_DIRECTED",
        reason_codes=["FILE_READ"],
        raw_output={"action": "READ_FILE"},
    )
    event_logger.log_event(
        session_id=session_id,
        actor="TOOL",
        event_type="TOOL_RESULT",
        tool_name="READ_FILE",
        target="report.txt",
        output_summary="file read success: report.txt",
        risk_level="MEDIUM",
        responsibility_type="USER_DIRECTED",
        reason_codes=["FILE_READ"],
        raw_output="일반 보고서 내용입니다.",
    )
    return event_logger.get_events(session_id)


def test_valid_event_chain_verifies_true(event_logger):
    events = _build_events(event_logger)
    assert HashChainBuilder().verify_chain(events) is True


def test_tampered_middle_event_fails_verification(event_logger):
    events = [_to_dict(event) for event in _build_events(event_logger)]
    tampered = deepcopy(events)
    tampered[1]["target"] = "secret.txt"
    assert HashChainBuilder().verify_chain(tampered) is False


def test_modified_previous_hash_fails_verification(event_logger):
    events = [_to_dict(event) for event in _build_events(event_logger)]
    tampered = deepcopy(events)
    tampered[2]["previous_event_hash"] = "sha256:deadbeef"
    assert HashChainBuilder().verify_chain(tampered) is False
