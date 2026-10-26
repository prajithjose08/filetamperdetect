"""
database.py
-----------
All SQLite database access lives here.

Two tables are created automatically when the application starts:
  - registered_files : trusted reference records (filename + SHA-256 hash).
  - verification_history : every integrity-check event with its result.

Using parameterised queries throughout prevents SQL injection.
"""

import sqlite3
import os
from datetime import datetime, timezone

# Path to the SQLite database file.
# The 'instance' folder is the conventional Flask location for runtime data.
DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "file_integrity.db")


def _get_connection() -> sqlite3.Connection:
    """Open and return a database connection with row_factory set."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # Rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL") # Better concurrent access
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """
    Create both tables if they do not already exist.
    Called once at application startup.
    """
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS registered_files (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT    NOT NULL,
                file_size   INTEGER NOT NULL,
                sha256_hash TEXT    NOT NULL,
                registered_at TEXT  NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS verification_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                registered_id   INTEGER,
                filename        TEXT    NOT NULL,
                original_hash   TEXT    NOT NULL,
                current_hash    TEXT    NOT NULL,
                file_size       INTEGER NOT NULL,
                result          TEXT    NOT NULL
                    CHECK(result IN ('UNCHANGED', 'MODIFIED', 'UNKNOWN')),
                verified_at     TEXT    NOT NULL,
                FOREIGN KEY (registered_id)
                    REFERENCES registered_files(id) ON DELETE CASCADE
            )
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# Registered Files
# ---------------------------------------------------------------------------

def register_file(filename: str, file_size: int, sha256_hash: str) -> int:
    """
    Insert a new trusted reference record.

    Returns:
        The auto-generated integer ID of the new record.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO registered_files (filename, file_size, sha256_hash, registered_at)
            VALUES (?, ?, ?, ?)
            """,
            (filename, file_size, sha256_hash, now),
        )
        conn.commit()
        return cur.lastrowid


def get_registered_file(record_id: int) -> sqlite3.Row | None:
    """Return one registered-file record by its primary key, or None."""
    with _get_connection() as conn:
        return conn.execute(
            "SELECT * FROM registered_files WHERE id = ?", (record_id,)
        ).fetchone()


def get_all_registered_files() -> list[sqlite3.Row]:
    """Return all registered-file records, newest first."""
    with _get_connection() as conn:
        return conn.execute(
            "SELECT * FROM registered_files ORDER BY registered_at DESC"
        ).fetchall()


def delete_registered_file(record_id: int) -> bool:
    """
    Delete a registered-file record and its associated history (CASCADE).
    Returns True if a row was deleted.
    """
    with _get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM registered_files WHERE id = ?", (record_id,)
        )
        conn.commit()
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Verification History
# ---------------------------------------------------------------------------

def add_verification(
    registered_id: int | None,
    filename: str,
    original_hash: str,
    current_hash: str,
    file_size: int,
    result: str,
) -> int:
    """
    Record one integrity-check event.

    The original reference hash is *never* changed here; only a snapshot is
    stored alongside the current hash and result.

    Returns:
        The auto-generated integer ID of the new history record.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO verification_history
                (registered_id, filename, original_hash, current_hash,
                 file_size, result, verified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (registered_id, filename, original_hash, current_hash,
             file_size, result, now),
        )
        conn.commit()
        return cur.lastrowid


def get_all_verifications(result_filter: str | None = None) -> list[sqlite3.Row]:
    """
    Return verification-history records, newest first.

    Args:
        result_filter: Optional string — 'UNCHANGED', 'MODIFIED', or 'UNKNOWN'.
                       If None, all records are returned.
    """
    with _get_connection() as conn:
        if result_filter:
            return conn.execute(
                """
                SELECT * FROM verification_history
                WHERE result = ?
                ORDER BY verified_at DESC
                """,
                (result_filter.upper(),),
            ).fetchall()
        return conn.execute(
            "SELECT * FROM verification_history ORDER BY verified_at DESC"
        ).fetchall()


def get_dashboard_stats() -> dict:
    """Return aggregate counts used by the dashboard."""
    with _get_connection() as conn:
        total_registered = conn.execute(
            "SELECT COUNT(*) FROM registered_files"
        ).fetchone()[0]
        total_checks = conn.execute(
            "SELECT COUNT(*) FROM verification_history"
        ).fetchone()[0]
        total_modified = conn.execute(
            "SELECT COUNT(*) FROM verification_history WHERE result = 'MODIFIED'"
        ).fetchone()[0]
        recent = conn.execute(
            """
            SELECT * FROM verification_history
            ORDER BY verified_at DESC LIMIT 5
            """
        ).fetchall()
    return {
        "total_registered": total_registered,
        "total_checks": total_checks,
        "total_modified": total_modified,
        "recent": recent,
    }
