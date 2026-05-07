# AgentTrace Architecture

## 1. 전체 구조도

```text
User Prompt
  ↓
Agent Simulator
  ↓
Planner
  ↓
Tool Wrapper
  ↓
Event Logger
  ↓
Hash Chain
  ↓
Risk Classifier
  ↓
Responsibility Classifier
  ↓
Causal Graph Builder
  ↓
Incident Report Generator
```

## 2. 컴포넌트 설명

- `Agent Simulator`: 실제 LLM 대신 사용자 입력과 문서 내용을 기반으로 계획과 도구 호출을 시뮬레이션합니다.
- `Planner`: 프롬프트와 문서에서 파일 접근, 외부 전송, 명령 실행 지시를 탐지해 결정적 계획을 생성합니다.
- `Tool Wrapper`: 실제 실행 없이 Mock 결과를 반환하면서 `TOOL_CALL`, `TOOL_RESULT` 이벤트를 남깁니다.
- `Event Logger`: 이벤트 ID, 타임스탬프, 요약, 해시, 이전 이벤트 해시를 기록합니다.
- `Hash Chain`: 세션별 이벤트를 체인으로 연결해 위변조 여부를 검증합니다.
- `Risk Classifier`: 민감 파일 접근, 외부 전송, 명령 실행 등의 위험도를 `LOW`부터 `CRITICAL`까지 분류합니다.
- `Responsibility Classifier`: 사용자의 직접 지시인지, 문서 유도인지, 도구 결과 유도인지, 정책 차단인지 구분합니다.
- `Causal Graph Builder`: `triggered_by_event_id`를 기준으로 원인 추적 그래프를 JSON으로 생성합니다.
- `Incident Report Generator`: Timeline, Evidence Hashes, Analysis를 포함한 Markdown 사고 리포트를 생성합니다.

## 3. 이벤트 흐름

1. `/agent/run`으로 `AgentRequest`를 입력받습니다.
2. `USER_PROMPT` 이벤트를 기록합니다.
3. 컨텍스트 문서가 있으면 `DOCUMENT_CONTEXT` 이벤트를 기록합니다.
4. Planner가 `AGENT_PLAN` 이벤트에 대응하는 계획을 생성합니다.
5. 각 도구 래퍼가 `TOOL_CALL`, `TOOL_RESULT` 이벤트를 기록합니다.
6. 정책 판단 결과를 `POLICY_DECISION` 이벤트로 남깁니다.
7. 최종 응답을 `FINAL_RESPONSE`로 기록합니다.
8. `CRITICAL` 또는 `BLOCK` 상황에서는 Markdown 사고 리포트를 생성하고 `INCIDENT_REPORT` 이벤트를 추가합니다.

## 4. Hash Chain 구조

- 각 `ForensicEvent`는 `previous_event_hash`를 포함합니다.
- `event_hash`는 이벤트 페이로드 전체와 `previous_event_hash`를 정규화 JSON으로 직렬화한 뒤 SHA-256으로 생성합니다.
- 세션 검증 시 각 이벤트의 이전 해시 연결과 현재 해시 재계산 값을 모두 비교합니다.

## 5. Causal Graph 구조

- 노드는 이벤트 단위입니다.
- 엣지는 `triggered_by_event_id`가 있으면 `triggered`, 없으면 순차 흐름 `sequential`로 생성됩니다.
- 문서 유도 또는 프롬프트 인젝션 이유 코드가 있는 첫 이벤트를 루트 원인 후보로 표시합니다.

## 6. Incident Report 생성 흐름

1. `CRITICAL` 또는 `BLOCK` 이벤트가 발생합니다.
2. 해당 세션의 이벤트 리스트와 그래프 JSON을 수집합니다.
3. Timeline, Evidence Hashes, Reason Codes, Analysis를 Markdown으로 렌더링합니다.
4. `reports/incident_{session_id}.md` 경로에 저장합니다.
