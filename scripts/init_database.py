"""Initialize the SentinelScope Starter SQLite database from the migration."""
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "sentinelscope.db"
MIGRATION_PATH = ROOT / "db" / "migrations" / "0001_starter_case_management.sql"


def main() -> None:
    DB_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as connection:
        connection.executescript(MIGRATION_PATH.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT OR IGNORE INTO users (id, email, display_name, role) VALUES (?, ?, ?, ?)",
            ("usr-alex-morgan", "alex.morgan@sentinelscope.demo", "Alex Morgan", "analyst"),
        )
        connection.execute(
            """INSERT OR IGNORE INTO cases
            (id, title, severity, status, owner_id, summary, next_step)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                "INC-2026-081", "Potential endpoint compromise", "critical", "investigating",
                "usr-alex-morgan", "C2-like TLS beaconing on WS-FIN-023.",
                "Validate endpoint process tree and isolate if confirmed.",
            ),
        )
        connection.execute("PRAGMA optimize")
        case_count = connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    print(f"Initialized {DB_PATH.name} with {case_count} case(s).")


if __name__ == "__main__":
    main()
