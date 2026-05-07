# AgentTrace Forensic Log Format

## 1. `ForensicEvent` 필드 설명

- `event_id`: 세션 내 순차 이벤트 식별자
- `session_id`: 동일 세션 이벤트 묶음 식별자
- `timestamp`: ISO-8601 형식 타임스탬프
- `actor`: `USER`, `AI_AGENT`, `TOOL`, `SYSTEM`
- `event_type`: 프롬프트, 계획, 도구 호출, 정책 판단 등 이벤트 유형
- `tool_name`: 관련 도구명
- `target`: 파일명, URL, 명령 문자열 등 대상
- `input_summary`: 원문 대신 저장하는 짧은 요약
- `output_summary`: 결과 원문 대신 저장하는 짧은 요약
- `risk_level`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `responsibility_type`: 책임 귀속 분류
- `reason_codes`: 탐지 근거 코드 목록
- `triggered_by_event_id`: 원인 이벤트 참조
- `input_hash`: 입력 원문의 SHA-256 증거 해시
- `output_hash`: 출력 원문의 SHA-256 증거 해시
- `previous_event_hash`: 직전 이벤트 해시
- `event_hash`: 현재 이벤트의 무결성 해시

## 2. `event_hash` 생성 방식

1. 이벤트 페이로드에서 `event_hash` 필드를 제외합니다.
2. `previous_event_hash`를 포함한 전체 payload를 canonical JSON으로 직렬화합니다.
3. UTF-8 문자열에 대해 SHA-256을 계산합니다.
4. `sha256:<hex>` 형식으로 저장합니다.

## 3. `previous_event_hash` 의미

- 세션 내 바로 이전 이벤트의 `event_hash`입니다.
- 이벤트 순서를 잇는 체인 포인터 역할을 합니다.
- 중간 이벤트가 수정되면 뒤 이벤트의 검증도 함께 실패합니다.

## 4. `input_hash`와 `output_hash` 의미

- 원문을 직접 저장하지 않고 증거성을 유지하기 위한 해시입니다.
- 프롬프트 원문, 문서 원문, 파일 내용, 외부 전송 페이로드, 명령 문자열을 해시로 보존합니다.

## 5. 원문 저장 최소화 정책

- 사용자 프롬프트 전체 저장 금지
- 민감 도구 결과 전체 저장 금지
- 문서 원문 전체의 장기 저장 지양
- 대신 요약과 해시 중심으로 저장

## 6. 로그 위변조 탐지 방식

- 세션 이벤트를 순서대로 순회하며 `previous_event_hash` 연결을 검증합니다.
- 각 이벤트의 해시를 재계산해 저장값과 비교합니다.
- 둘 중 하나라도 불일치하면 위변조로 판단합니다.
