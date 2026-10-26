"""
tests/test_integration.py
--------------------------
End-to-end integration tests using Flask's built-in test client.
No real network or background process needed.

Run with:  python -m pytest tests/ -v
"""

import io
import sys
import os
import json
import csv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Use a fresh in-memory database for every test session
os.environ["FTD_TEST_DB"] = ":memory:"

import database as db
import hash_utils


# ---------------------------------------------------------------------------
# Patch database to use :memory: before importing app
# ---------------------------------------------------------------------------
_original_get_connection = db._get_connection
import sqlite3

def _test_connection():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# We'll use the real app but swap to a temp file DB per test
import tempfile
import pytest

@pytest.fixture()
def client(tmp_path):
    """Create a Flask test client backed by a temporary SQLite database."""
    # Point db module at a fresh temp file
    tmp_db = str(tmp_path / "test_integrity.db")
    original = db.DB_PATH
    db.DB_PATH = tmp_db
    db.init_db()

    import app as flask_app
    flask_app.app.config["TESTING"] = True
    flask_app.app.config["WTF_CSRF_ENABLED"] = False

    with flask_app.app.test_client() as c:
        yield c

    db.DB_PATH = original


def _make_upload(filename: str, content: bytes, content_type: str = "text/plain"):
    """Helper: return a FileStorage-like tuple for test_client.post()."""
    return (io.BytesIO(content), filename)


# ---------------------------------------------------------------------------
# Route smoke tests
# ---------------------------------------------------------------------------

class TestRoutes:
    def test_dashboard_200(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"Dashboard" in r.data

    def test_register_get_200(self, client):
        r = client.get("/register")
        assert r.status_code == 200
        assert b"Register" in r.data

    def test_verify_get_200(self, client):
        r = client.get("/verify")
        assert r.status_code == 200

    def test_history_get_200(self, client):
        r = client.get("/history")
        assert r.status_code == 200

    def test_security_info_200(self, client):
        r = client.get("/security-info")
        assert r.status_code == 200
        assert b"SHA-256" in r.data

    def test_export_csv_200(self, client):
        r = client.get("/export/csv")
        assert r.status_code == 200
        assert b"History ID" in r.data  # CSV header


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------

class TestRegistration:
    def test_register_file(self, client):
        """Registering a file returns 200 and shows Record ID."""
        r = client.post(
            "/register",
            data={"file": _make_upload("hello.txt", b"Hello, World!")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200
        assert b"Record ID" in r.data
        assert b"hello.txt" in r.data

    def test_register_stores_in_db(self, client):
        """After registration, the API returns the record."""
        client.post(
            "/register",
            data={"file": _make_upload("stored.txt", b"stored content")},
            content_type="multipart/form-data",
        )
        r = client.get("/api/registered")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert len(data) == 1
        assert data[0]["filename"] == "stored.txt"
        assert len(data[0]["sha256_hash"]) == 64

    def test_register_empty_file(self, client):
        """An empty file (0 bytes) can be registered."""
        r = client.post(
            "/register",
            data={"file": _make_upload("empty.txt", b"")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200
        assert b"Record ID" in r.data

    def test_register_no_file(self, client):
        """Missing file field redirects back."""
        r = client.post("/register", data={}, content_type="multipart/form-data",
                        follow_redirects=True)
        assert r.status_code == 200
        assert b"No file" in r.data

    def test_register_two_identical_files(self, client):
        """Two files with the same content produce the same hash but separate records."""
        content = b"identical content"
        client.post("/register", data={"file": _make_upload("a.txt", content)},
                    content_type="multipart/form-data")
        client.post("/register", data={"file": _make_upload("b.txt", content)},
                    content_type="multipart/form-data")
        r = client.get("/api/registered")
        records = json.loads(r.data)
        assert len(records) == 2
        assert records[0]["sha256_hash"] == records[1]["sha256_hash"]
        assert records[0]["id"] != records[1]["id"]


# ---------------------------------------------------------------------------
# Verification tests
# ---------------------------------------------------------------------------

class TestVerification:
    def _register(self, client, filename: str, content: bytes) -> int:
        """Register a file and return its record ID."""
        client.post(
            "/register",
            data={"file": _make_upload(filename, content)},
            content_type="multipart/form-data",
        )
        records = json.loads(client.get("/api/registered").data)
        return records[-1]["id"]

    def test_verify_unchanged(self, client):
        """Verifying with identical content → UNCHANGED."""
        content = b"The document has not changed."
        record_id = self._register(client, "doc.txt", content)
        r = client.post(
            "/verify",
            data={"file": _make_upload("doc.txt", content), "record_id": record_id},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200
        assert b"UNCHANGED" in r.data

    def test_verify_modified(self, client):
        """Verifying with different content → MODIFIED."""
        original = b"Original content."
        tampered = b"Original content!!!"
        record_id = self._register(client, "doc.txt", original)
        r = client.post(
            "/verify",
            data={"file": _make_upload("doc.txt", tampered), "record_id": record_id},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200
        assert b"MODIFIED" in r.data

    def test_verify_reference_hash_unchanged_after_modified(self, client):
        """
        After a MODIFIED check, the original reference hash must still equal
        the hash of the originally registered content.
        """
        original = b"Original trusted content."
        tampered = b"Tampered content."
        record_id = self._register(client, "doc.txt", original)

        # Run a verify that produces MODIFIED
        client.post(
            "/verify",
            data={"file": _make_upload("doc.txt", tampered), "record_id": record_id},
            content_type="multipart/form-data",
        )

        # Check that reference hash is still the original
        records = json.loads(client.get("/api/registered").data)
        ref = next(r for r in records if r["id"] == record_id)
        expected_ref_hash = hash_utils.compute_hash_from_bytes(original)
        assert ref["sha256_hash"] == expected_ref_hash, \
            "Reference hash was overwritten after a failed integrity check!"

    def test_verify_unknown_record_id(self, client):
        """Using a non-existent record ID → UNKNOWN."""
        r = client.post(
            "/verify",
            data={"file": _make_upload("x.txt", b"data"), "record_id": 9999},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200
        assert b"UNKNOWN" in r.data

    def test_verify_empty_file(self, client):
        """Empty file can be registered and verified."""
        record_id = self._register(client, "empty.txt", b"")
        r = client.post(
            "/verify",
            data={"file": _make_upload("empty.txt", b""), "record_id": record_id},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200
        assert b"UNCHANGED" in r.data

    def test_verify_special_filename(self, client):
        """
        werkzeug.secure_filename strips special characters.
        The hash should still be computed from the content correctly.
        """
        content = b"Special file content"
        record_id = self._register(client, "report (final v2).txt", content)
        r = client.post(
            "/verify",
            data={
                "file": _make_upload("report (final v2).txt", content),
                "record_id": record_id,
            },
            content_type="multipart/form-data",
        )
        assert r.status_code == 200
        assert b"UNCHANGED" in r.data


# ---------------------------------------------------------------------------
# History & persistence tests
# ---------------------------------------------------------------------------

class TestHistory:
    def _register_and_verify(self, client, content: bytes, modified_content=None):
        client.post("/register",
                    data={"file": _make_upload("f.txt", content)},
                    content_type="multipart/form-data")
        records = json.loads(client.get("/api/registered").data)
        rid = records[-1]["id"]
        verify_content = modified_content if modified_content is not None else content
        client.post("/verify",
                    data={"file": _make_upload("f.txt", verify_content), "record_id": rid},
                    content_type="multipart/form-data")

    def test_history_persists(self, client):
        """History records are returned on the history page."""
        self._register_and_verify(client, b"persist test")
        r = client.get("/history")
        assert r.status_code == 200
        assert b"UNCHANGED" in r.data

    def test_filter_modified(self, client):
        """filter=MODIFIED returns only MODIFIED records."""
        self._register_and_verify(client, b"original", b"tampered")
        r = client.get("/history?filter=MODIFIED")
        assert r.status_code == 200
        assert b"MODIFIED" in r.data

    def test_filter_unchanged(self, client):
        self._register_and_verify(client, b"unchanged file")
        r = client.get("/history?filter=UNCHANGED")
        assert r.status_code == 200
        assert b"UNCHANGED" in r.data

    def test_filter_unknown(self, client):
        """Verifying against non-existent record produces UNKNOWN in history."""
        client.post("/verify",
                    data={"file": _make_upload("x.txt", b"data"), "record_id": 9999},
                    content_type="multipart/form-data")
        r = client.get("/history?filter=UNKNOWN")
        assert r.status_code == 200
        assert b"UNKNOWN" in r.data

    def test_invalid_filter_returns_all(self, client):
        """An invalid filter value should not crash — return all records."""
        r = client.get("/history?filter=INVALID_VALUE")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# CSV export tests
# ---------------------------------------------------------------------------

class TestCSVExport:
    def test_csv_header(self, client):
        r = client.get("/export/csv")
        assert r.status_code == 200
        lines = r.data.decode("utf-8").strip().splitlines()
        header = next(csv.reader(lines))
        assert "History ID" in header
        assert "Result" in header

    def test_csv_contains_records(self, client):
        """After a verification, the CSV should contain that record."""
        client.post("/register",
                    data={"file": _make_upload("csvtest.txt", b"csv test content")},
                    content_type="multipart/form-data")
        records = json.loads(client.get("/api/registered").data)
        rid = records[0]["id"]
        client.post("/verify",
                    data={"file": _make_upload("csvtest.txt", b"csv test content"),
                          "record_id": rid},
                    content_type="multipart/form-data")

        r = client.get("/export/csv")
        content = r.data.decode("utf-8")
        assert "UNCHANGED" in content
        assert "csvtest.txt" in content

    def test_csv_filter(self, client):
        """CSV export respects the filter parameter — both MODIFIED and UNCHANGED rows exist."""
        # Register one file
        client.post("/register",
                    data={"file": _make_upload("filt.txt", b"original")},
                    content_type="multipart/form-data")
        records = json.loads(client.get("/api/registered").data)
        rid = records[0]["id"]

        # Produce a MODIFIED verification event
        client.post("/verify",
                    data={"file": _make_upload("filt.txt", b"tampered"),
                          "record_id": rid},
                    content_type="multipart/form-data")

        # Produce an UNCHANGED verification event
        client.post("/verify",
                    data={"file": _make_upload("filt.txt", b"original"),
                          "record_id": rid},
                    content_type="multipart/form-data")

        r_mod  = client.get("/export/csv?filter=MODIFIED")
        r_unch = client.get("/export/csv?filter=UNCHANGED")
        assert b"MODIFIED"  in r_mod.data
        assert b"UNCHANGED" not in r_mod.data
        assert b"UNCHANGED" in r_unch.data
        assert b"MODIFIED"  not in r_unch.data
