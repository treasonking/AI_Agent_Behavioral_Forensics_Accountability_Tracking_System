from backend.app.forensic.event_logger import ForensicEventLogger


def test_event_creation_includes_event_id(event_logger: ForensicEventLogger):
    session_id = event_logger.start_session("sess-logger-001")
    event = event_logger.log_event(
        session_id=session_id,
        actor="USER",
        event_type="USER_PROMPT",
        input_summary="user prompt received",
        risk_level="LOW",
        responsibility_type="USER_DIRECTED",
        reason_codes=["SAFE_PROMPT"],
        raw_input="이 문서를 요약해줘.",
    )
    assert event.event_id.startswith("evt-")


def test_event_creation_includes_event_hash(event_logger: ForensicEventLogger):
    session_id = event_logger.start_session("sess-logger-002")
    event = event_logger.log_event(
        session_id=session_id,
        actor="USER",
        event_type="USER_PROMPT",
        input_summary="user prompt received",
        risk_level="LOW",
        responsibility_type="USER_DIRECTED",
        reason_codes=["SAFE_PROMPT"],
        raw_input="이 문서를 요약해줘.",
    )
    assert event.event_hash.startswith("sha256:")


def test_second_event_links_previous_hash(event_logger: ForensicEventLogger):
    session_id = event_logger.start_session("sess-logger-003")
    first = event_logger.log_event(
        session_id=session_id,
        actor="USER",
        event_type="USER_PROMPT",
        input_summary="prompt",
        risk_level="LOW",
        responsibility_type="USER_DIRECTED",
        reason_codes=["SAFE_PROMPT"],
        raw_input="hello",
    )
    second = event_logger.log_event(
        session_id=session_id,
        actor="AI_AGENT",
        event_type="AGENT_PLAN",
        output_summary="SAFE_SUMMARY",
        risk_level="LOW",
        responsibility_type="USER_DIRECTED",
        reason_codes=["SAFE_PROMPT"],
        raw_output={"action": "SAFE_SUMMARY"},
    )
    assert second.previous_event_hash == first.event_hash


def test_session_verification_returns_true(event_logger: ForensicEventLogger):
    session_id = event_logger.start_session("sess-logger-004")
    event_logger.log_event(
        session_id=session_id,
        actor="USER",
        event_type="USER_PROMPT",
        input_summary="prompt",
        risk_level="LOW",
        responsibility_type="USER_DIRECTED",
        reason_codes=["SAFE_PROMPT"],
        raw_input="hello",
    )
    event_logger.log_event(
        session_id=session_id,
        actor="AI_AGENT",
        event_type="FINAL_RESPONSE",
        output_summary="요청이 안전하게 처리되었습니다.",
        risk_level="LOW",
        responsibility_type="USER_DIRECTED",
        reason_codes=["SAFE_PROMPT"],
        raw_output="요청이 안전하게 처리되었습니다.",
    )
    assert event_logger.verify_session(session_id) is True


def test_long_summary_is_truncated(event_logger: ForensicEventLogger):
    session_id = event_logger.start_session("sess-logger-005")
    long_summary = "a" * 300
    event = event_logger.log_event(
        session_id=session_id,
        actor="USER",
        event_type="USER_PROMPT",
        input_summary=long_summary,
        risk_level="LOW",
        responsibility_type="USER_DIRECTED",
        reason_codes=["SAFE_PROMPT"],
        raw_input=long_summary,
    )
    assert len(event.input_summary) <= 160
    assert event.input_summary.endswith("...")
