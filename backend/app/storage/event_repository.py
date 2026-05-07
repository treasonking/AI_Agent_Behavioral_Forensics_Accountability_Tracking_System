import json
import sqlite3
import threading
from pathlib import Path
from typing import List

from backend.app.database import DEFAULT_DB_PATH, ensure_parent_dir
from backend.app.models.schemas import ForensicEvent


class EventRepository:
    """Persist forensic events in a lightweight SQLite database."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            ensure_parent_dir(Path(self.db_path))
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(self.db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._lock:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS forensic_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    tool_name TEXT,
                    target TEXT,
                    input_summary TEXT,
                    output_summary TEXT,
                    risk_level TEXT NOT NULL,
                    responsibility_type TEXT NOT NULL,
                    reason_codes TEXT NOT NULL,
                    triggered_by_event_id TEXT,
                    input_hash TEXT,
                    output_hash TEXT,
                    previous_event_hash TEXT,
                    event_hash TEXT NOT NULL
                )
                """
            )
            self._connection.commit()

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            self._connection.execute(
                "DELETE FROM forensic_events WHERE session_id = ?",
                (session_id,),
            )
            self._connection.commit()

    def save_event(self, event: ForensicEvent) -> None:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO forensic_events (
                    session_id,
                    event_id,
                    timestamp,
                    actor,
                    event_type,
                    tool_name,
                    target,
                    input_summary,
                    output_summary,
                    risk_level,
                    responsibility_type,
                    reason_codes,
                    triggered_by_event_id,
                    input_hash,
                    output_hash,
                    previous_event_hash,
                    event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.session_id,
                    event.event_id,
                    event.timestamp,
                    event.actor,
                    event.event_type,
                    event.tool_name,
                    event.target,
                    event.input_summary,
                    event.output_summary,
                    event.risk_level,
                    event.responsibility_type,
                    json.dumps(event.reason_codes, ensure_ascii=False),
                    event.triggered_by_event_id,
                    event.input_hash,
                    event.output_hash,
                    event.previous_event_hash,
                    event.event_hash,
                ),
            )
            self._connection.commit()

    def get_events(self, session_id: str) -> List[ForensicEvent]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT
                    session_id,
                    event_id,
                    timestamp,
                    actor,
                    event_type,
                    tool_name,
                    target,
                    input_summary,
                    output_summary,
                    risk_level,
                    responsibility_type,
                    reason_codes,
                    triggered_by_event_id,
                    input_hash,
                    output_hash,
                    previous_event_hash,
                    event_hash
                FROM forensic_events
                WHERE session_id = ?
                ORDER BY id ASC
                """,
                (session_id,),
            ).fetchall()

        events: List[ForensicEvent] = []
        for row in rows:
            events.append(
                ForensicEvent(
                    session_id=row["session_id"],
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    actor=row["actor"],
                    event_type=row["event_type"],
                    tool_name=row["tool_name"],
                    target=row["target"],
                    input_summary=row["input_summary"],
                    output_summary=row["output_summary"],
                    risk_level=row["risk_level"],
                    responsibility_type=row["responsibility_type"],
                    reason_codes=json.loads(row["reason_codes"]),
                    triggered_by_event_id=row["triggered_by_event_id"],
                    input_hash=row["input_hash"],
                    output_hash=row["output_hash"],
                    previous_event_hash=row["previous_event_hash"],
                    event_hash=row["event_hash"],
                )
            )
        return events
