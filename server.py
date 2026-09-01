"""SentinelScope Starter local API and dashboard server (standard library only)."""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "data" / "sentinelscope.db"


def get_cases() -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT c.id, c.title, c.severity AS priority, c.status, c.next_step,
                      c.opened_at, COALESCE(u.display_name, 'Unassigned') AS owner
               FROM cases c LEFT JOIN users u ON u.id = c.owner_id
               ORDER BY CASE c.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                       WHEN 'medium' THEN 3 ELSE 4 END, c.updated_at DESC"""
        ).fetchall()
    return [dict(row) | {"sla": "00:18:42" if row["priority"] == "critical" else "03:42:10"} for row in rows]


def create_case(payload: dict) -> dict:
    case_id = f"INC-{datetime.now(timezone.utc):%Y}-{uuid.uuid4().hex[:4].upper()}"
    title = str(payload.get("title", "New analyst investigation"))[:120]
    severity = payload.get("severity", "medium")
    if severity not in {"critical", "high", "medium", "low"}:
        severity = "medium"
    with sqlite3.connect(DATABASE) as connection:
        connection.execute(
            """INSERT INTO cases (id, title, severity, status, owner_id, summary, next_step)
               VALUES (?, ?, ?, 'new', 'usr-alex-morgan', ?, ?)""",
            (case_id, title, severity, "Created from the SentinelScope Starter interface.", "Attach related alerts"),
        )
        connection.execute(
            "INSERT INTO audit_log (id, actor_id, case_id, action, detail_json) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), "usr-alex-morgan", case_id, "case.created", json.dumps({"source": "web"})),
        )
    return next(case for case in get_cases() if case["id"] == case_id)


def get_case_notes(case_id: str) -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT n.id, n.body, n.created_at, COALESCE(u.display_name, 'System') AS author
               FROM case_notes n LEFT JOIN users u ON u.id = n.author_id
               WHERE n.case_id = ? ORDER BY n.created_at DESC""", (case_id,)
        ).fetchall()
    return [dict(row) for row in rows]


def update_case(case_id: str, payload: dict) -> dict | None:
    status = payload.get("status")
    if status not in {"new", "investigating", "contained", "resolved", "closed"}:
        return None
    with sqlite3.connect(DATABASE) as connection:
        cursor = connection.execute(
            "UPDATE cases SET status = ?, updated_at = CURRENT_TIMESTAMP, closed_at = CASE WHEN ? IN ('resolved', 'closed') THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id = ?",
            (status, status, case_id),
        )
        if not cursor.rowcount:
            return None
        connection.execute(
            "INSERT INTO audit_log (id, actor_id, case_id, action, detail_json) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), "usr-alex-morgan", case_id, "case.status_changed", json.dumps({"status": status})),
        )
    return next(case for case in get_cases() if case["id"] == case_id)


def add_note(case_id: str, payload: dict) -> dict | None:
    body = str(payload.get("body", "")).strip()[:2000]
    if not body:
        return None
    note_id = str(uuid.uuid4())
    with sqlite3.connect(DATABASE) as connection:
        exists = connection.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not exists:
            return None
        connection.execute("INSERT INTO case_notes (id, case_id, author_id, body) VALUES (?, ?, ?, ?)", (note_id, case_id, "usr-alex-morgan", body))
        connection.execute("INSERT INTO audit_log (id, actor_id, case_id, action, detail_json) VALUES (?, ?, ?, ?, ?)", (str(uuid.uuid4()), "usr-alex-morgan", case_id, "case.note_added", json.dumps({"note_id": note_id})))
    return get_case_notes(case_id)[0]


class SentinelHandler(SimpleHTTPRequestHandler):
    def _json(self, status: HTTPStatus, body: object) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/cases":
            self._json(HTTPStatus.OK, {"cases": get_cases()})
            return
        if path.startswith("/api/cases/") and path.endswith("/notes"):
            self._json(HTTPStatus.OK, {"notes": get_case_notes(path.split("/")[3])})
            return
        super().do_GET()

    def do_POST(self) -> None:
        try:
            size = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(size) or b"{}")
            path = urlparse(self.path).path
            if path == "/api/cases":
                self._json(HTTPStatus.CREATED, {"case": create_case(payload)})
            elif path.startswith("/api/cases/") and path.endswith("/notes"):
                note = add_note(path.split("/")[3], payload)
                self._json(HTTPStatus.CREATED, {"note": note} if note else {"error": "Case or note body not found"})
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
        except (ValueError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid case payload"})

    def do_PATCH(self) -> None:
        try:
            path = urlparse(self.path).path
            if not path.startswith("/api/cases/"):
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
                return
            size = int(self.headers.get("Content-Length", "0"))
            case = update_case(path.split("/")[3], json.loads(self.rfile.read(size) or b"{}"))
            self._json(HTTPStatus.OK, {"case": case} if case else {"error": "Case or status not found"})
        except (ValueError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid case payload"})


if __name__ == "__main__":
    address = ("127.0.0.1", 8000)
    print(f"SentinelScope Starter is running at http://{address[0]}:{address[1]}")
    ThreadingHTTPServer(address, SentinelHandler).serve_forever()
