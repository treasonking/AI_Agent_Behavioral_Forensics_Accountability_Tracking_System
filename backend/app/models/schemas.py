from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AgentRequest(BaseModel):
    session_id: Optional[str] = None
    user_prompt: str
    context_documents: Optional[List[Dict[str, str]]] = None


class ForensicEvent(BaseModel):
    event_id: str
    session_id: str
    timestamp: str
    actor: str
    event_type: str
    tool_name: Optional[str] = None
    target: Optional[str] = None
    input_summary: Optional[str] = None
    output_summary: Optional[str] = None
    risk_level: str
    responsibility_type: str
    reason_codes: List[str] = Field(default_factory=list)
    triggered_by_event_id: Optional[str] = None
    input_hash: Optional[str] = None
    output_hash: Optional[str] = None
    previous_event_hash: Optional[str] = None
    event_hash: str


class AgentResponse(BaseModel):
    session_id: str
    final_response: str
    action: str
    risk_level: str
    events: List[ForensicEvent] = Field(default_factory=list)
    incident_report_path: Optional[str] = None
    graph: Optional[Dict[str, Any]] = None


class IncidentReport(BaseModel):
    incident_id: str
    session_id: str
    risk_level: str
    summary: str
    timeline: List[ForensicEvent] = Field(default_factory=list)
    root_cause_event_id: Optional[str] = None
    causal_chain: List[str] = Field(default_factory=list)
    evidence_hashes: Dict[str, str] = Field(default_factory=dict)
