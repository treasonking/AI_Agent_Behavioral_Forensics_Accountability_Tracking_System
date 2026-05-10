[![CI](https://github.com/treasonking/AI_Agent_Behavioral_Forensics_Accountability_Tracking_System/actions/workflows/ci.yml/badge.svg)](https://github.com/treasonking/AI_Agent_Behavioral_Forensics_Accountability_Tracking_System/actions/workflows/ci.yml)

# AgentTrace

AgentTrace는 AI Agent의 자율 행동 과정에서 발생하는 프롬프트, 도구 호출, 데이터 접근, 외부 전송 시도를 포렌식 로그로 기록하고, SHA-256 Hash Chain과 책임 추적 그래프를 통해 사고 원인을 분석하는 시스템입니다.

AI Agent의 자율 행동에 대해 디지털 포렌식 관점의 감사 추적과 책임 소재 분석을 제공하는 시스템을 구현했습니다.

FastAPI 기반 Agent Runtime에서 발생하는 Tool Call 이벤트를 수집하고, SHA-256 Hash Chain, Risk Classification, Responsibility Classification, Causal Graph를 통해 AI Agent 행동의 무결성 검증과 사고 원인 추적을 구현했습니다.

## 프로젝트 소개

AgentTrace는 AI Agent의 프롬프트, 도구 호출, 데이터 접근, 외부 전송 시도를 포렌식 로그로 기록하고, SHA-256 기반 증거 해시와 책임 추적 그래프를 통해 사고 원인을 분석하는 시스템입니다.

## 문제 배경

- AI Agent는 사용자를 대신해 파일, 웹, 명령 실행 도구를 호출할 수 있습니다.
- 사고 발생 시 사용자가 직접 지시한 행동인지, 문서 내부 악성 지시 때문인지, Agent가 자율적으로 수행한 행동인지 구분하기 어렵습니다.
- 따라서 Agent 행동을 감사 가능한 이벤트 단위로 기록하고, 원인 흐름을 추적하는 포렌식 시스템이 필요합니다.

## 주요 기능

- Agent 행동 로그
- Tool Call 추적
- 위험 행동 분류
- 책임 유형 분류
- Hash Chain 기반 로그 무결성 검증
- Causal Graph 생성
- Incident Report 자동 생성

## 아키텍처

```text
User Prompt
↓
Agent Simulator
↓
Tool Wrapper
↓
Forensic Event Logger
↓
Hash Chain
↓
Risk Classifier
↓
Causal Graph Builder
↓
Incident Report Generator
```

## 디렉터리 개요

- [backend/app/main.py](./backend/app/main.py)
- [backend/app/agent/simulator.py](./backend/app/agent/simulator.py)
- [backend/app/forensic/event_logger.py](./backend/app/forensic/event_logger.py)
- [backend/app/reports/report_generator.py](./backend/app/reports/report_generator.py)
- [docs/architecture.md](./docs/architecture.md)
- [docs/threat_model.md](./docs/threat_model.md)
- [docs/forensic_log_format.md](./docs/forensic_log_format.md)
- [docs/evaluation.md](./docs/evaluation.md)

## 실행 방법

```bash
pip install -r requirements.txt
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

## Docker 실행

```bash
docker compose up --build
```

기본적으로 API는 `http://127.0.0.1:8000`에서 실행되며, 생성 리포트는 `./reports` 볼륨에 유지됩니다.

## 테스트 방법

```bash
pytest backend/tests -v
```

검증 결과:

- `pytest backend/tests -v` 기준 `45 passed in 1.82s`
- `/health` 경로 응답 확인 완료
- `/agent/run` 외부 전송 시나리오에서 `BLOCK / CRITICAL / incident report generated` 확인 완료

## API 사용 예시

```bash
curl -X POST http://127.0.0.1:8000/agent/run \
  -H "Content-Type: application/json" \
  -d @examples/scenario_03_external_transfer.json
```

## 데모 시나리오

- Safe Prompt
- Prompt Injection File Read
- External Transfer Attempt
- Command Execution Attempt

## 샘플 결과물

- [Sample Incident Report](./reports/sample_incident_report.md)
- [Sample Causal Graph](./reports/sample_causal_graph.json)

## 실행 결과 예시

```json
{
  "session_id": "sess-exfil-001",
  "final_response": "외부 전송 시도가 감지되어 차단되었습니다. 사고 리포트가 생성되었습니다.",
  "action": "BLOCK",
  "risk_level": "CRITICAL",
  "incident_report_path": "reports/incident_sess-exfil-001.md"
}
```

## 문서

- [Architecture](./docs/architecture.md)
- [Threat Model](./docs/threat_model.md)
- [Forensic Log Format](./docs/forensic_log_format.md)
- [API Spec](./docs/api_spec.md)
- [Evaluation](./docs/evaluation.md)

## 포트폴리오 어필 문장

AgentTrace는 AI Agent의 자율 행동 과정에서 발생하는 프롬프트, 도구 호출, 데이터 접근, 외부 전송 시도를 포렌식 로그로 기록하고, SHA-256 Hash Chain과 책임 추적 그래프를 통해 사고 원인을 분석하는 시스템입니다.
