# AgentTrace Evaluation

## 1. 기능 테스트

| Scenario | Expected Action | Actual Action | Risk Level | Report Generated | Pass |
|---|---|---|---|---|---|
| Safe Prompt | ALLOW | ALLOW | LOW | No | Yes |
| Prompt Injection File Read | WARN or BLOCK | WARN | HIGH | No | Yes |
| External Transfer Attempt | BLOCK | BLOCK | CRITICAL | Yes | Yes |
| Command Execution Attempt | BLOCK | BLOCK | CRITICAL | Yes | Yes |

## 2. 보안성 평가

- 민감 원문은 `input_hash`, `output_hash`로만 보존하고 리포트에는 전체 문자열을 기록하지 않습니다.
- `HashChainBuilder.verify_chain()`으로 세션 로그 위변조 여부를 검증합니다.
- 위험 행동은 `RiskClassifier`에서 파일 접근, 외부 전송, 명령 실행 기준으로 분류합니다.
- 추가 탐지 규칙으로 `client_secret`, `bearer`, `access_key`, `webhook`, `wget`, `certutil` 등 포트폴리오 설명력이 높은 키워드를 포함했습니다.

## 3. 포렌식 적합성 평가

- 사고 타임라인: `ForensicEvent` 리스트와 보고서 Timeline 표로 생성됩니다.
- 원인 이벤트 추적: `triggered_by_event_id`와 `CausalGraphBuilder`로 추적합니다.
- 증거 해시 생성: 모든 주요 입력과 결과에 대해 SHA-256 해시를 생성합니다.
- 리포트 자동 생성: `CRITICAL` 또는 `BLOCK` 발생 시 Markdown 리포트를 생성합니다.

## 4. 배포 및 재현성

- `requirements.txt`는 실제 런타임에 필요한 패키지만 남겨 설치 표면을 줄였습니다.
- 로컬 실행은 `uvicorn`, 컨테이너 실행은 `docker compose up --build` 기준으로 문서화했습니다.
- CI는 GitHub Actions에서 `pytest backend/tests -v`를 자동 실행하도록 구성했습니다.
- 샘플 산출물은 [sample_incident_report.md](./../reports/sample_incident_report.md)와 [sample_causal_graph.json](./../reports/sample_causal_graph.json)로 함께 제공합니다.

## 5. 테스트 메모

- 구현 기준 테스트 파일은 `backend/tests/` 아래에 작성되어 있습니다.
- `pytest backend/tests -v` 실행 결과: `45 passed in 1.82s`
- FastAPI 라우트 함수 직접 호출 검증 결과:
  - `/health` 응답: `{"status": "ok", "service": "AgentTrace"}`
  - `/agent/run` 악성 외부 전송 시나리오 응답: `action=BLOCK`, `risk_level=CRITICAL`, `incident_report_path` 생성 확인
