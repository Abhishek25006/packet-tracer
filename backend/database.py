"""
Simple SQLite storage for NetPulse capture sessions.

Stores one row per capture session (live capture or pcap analysis)
with its summary report as JSON — not individual packets, to keep
the database small and fast.
"""

import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "netpulse.db")


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,              -- 'live' or 'pcap'
                label TEXT,                        -- e.g. filename or interface name
                started_at TEXT NOT NULL,
                ended_at TEXT,
                packet_count INTEGER DEFAULT 0,
                summary_json TEXT                  -- full generate_summary() output
            )
        """)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def create_session(source: str, label: str | None = None) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO sessions (source, label, started_at) VALUES (?, ?, ?)",
            (source, label, datetime.now().isoformat()),
        )
        conn.commit()
        return cur.lastrowid


def finish_session(session_id: int, summary: dict):
    with get_conn() as conn:
        conn.execute(
            """UPDATE sessions
               SET ended_at = ?, packet_count = ?, summary_json = ?
               WHERE id = ?""",
            (
                datetime.now().isoformat(),
                summary.get("total_packets", 0),
                json.dumps(summary),
                session_id,
            ),
        )
        conn.commit()


def list_sessions(limit: int = 50):
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, source, label, started_at, ended_at, packet_count
               FROM sessions ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_session(session_id: int):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        if result.get("summary_json"):
            result["summary"] = json.loads(result["summary_json"])
            del result["summary_json"]
        return result


def delete_session(session_id: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()