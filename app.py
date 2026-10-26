"""
app.py
------
Main Flask application.

Registers all routes, enforces upload limits, generates server-side hashes,
and never exposes internal tracebacks to the browser.

Run with:
    python app.py
"""

import csv
import io
import os
import secrets
import tempfile

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    Response,
    abort,
)
from werkzeug.utils import secure_filename

import database as db
import hash_utils

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = Flask(__name__)

# A random secret key is generated each run.  For persistent sessions across
# restarts, replace this with a fixed string or an environment variable.
app.secret_key = secrets.token_hex(32)

# Maximum upload size: 50 MiB.  Adjust as needed.
MAX_CONTENT_LENGTH_MB = 50
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH_MB * 1024 * 1024

# Allowed MIME-related extensions.  Flask/Werkzeug checks content length but
# not extension — we do our own extension check below.
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif", "bmp", "webp",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "tar", "gz", "7z",
    "csv", "json", "xml", "html", "htm", "md",
    "py", "js", "ts", "css", "java", "c", "cpp", "h", "cs",
    "mp3", "wav", "mp4", "avi", "mov",
    "iso", "bin", "exe", "dll",
}


def _allowed_file(filename: str) -> bool:
    """Return True if the extension is in ALLOWED_EXTENSIONS."""
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ---------------------------------------------------------------------------
# Custom Jinja2 filters
# ---------------------------------------------------------------------------

@app.template_filter("filesizeformat")
def filesizeformat_filter(value: int) -> str:
    """Convert a byte count into a human-readable string (e.g. 1.4 KiB)."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return "0 B"
    if value == 0:
        return "0 B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024:
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} B"
        value /= 1024
    return f"{value:.1f} PiB"


# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------

with app.app_context():
    db.init_db()


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(413)
def too_large(_e):
    flash(
        f"File too large. Maximum allowed size is {MAX_CONTENT_LENGTH_MB} MiB.",
        "error",
    )
    return redirect(url_for("register")), 413


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(_e):
    # Never show the real traceback to the browser.
    return render_template("500.html"), 500


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    stats = db.get_dashboard_stats()
    return render_template("index.html", stats=stats)


# ---------------------------------------------------------------------------
# File Registration
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part in the request.", "error")
            return redirect(request.url)

        uploaded = request.files["file"]

        if uploaded.filename == "":
            flash("No file selected.", "error")
            return redirect(request.url)

        filename = secure_filename(uploaded.filename)

        if not _allowed_file(filename):
            flash(
                "File type not allowed. Please upload a common document, "
                "image, archive, or source-code file.",
                "error",
            )
            return redirect(request.url)

        # Write to a temporary file so we can hash it safely,
        # then delete it — we never store the raw file permanently.
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name
                uploaded.save(tmp_path)

            file_size = os.path.getsize(tmp_path)

            with open(tmp_path, "rb") as fh:
                sha256 = hash_utils.compute_hash_from_stream(fh)

        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)

        record_id = db.register_file(filename, file_size, sha256)

        flash(
            f"File registered successfully! Record ID: {record_id}",
            "success",
        )
        return render_template(
            "register.html",
            success=True,
            record_id=record_id,
            filename=filename,
            file_size=file_size,
            sha256=sha256,
        )

    return render_template("register.html", success=False)


# ---------------------------------------------------------------------------
# File Integrity Verification
# ---------------------------------------------------------------------------

@app.route("/verify", methods=["GET", "POST"])
def verify():
    registered_files = db.get_all_registered_files()

    if request.method == "POST":
        record_id_str = request.form.get("record_id", "").strip()
        if "file" not in request.files:
            flash("No file part in the request.", "error")
            return redirect(request.url)

        uploaded = request.files["file"]

        if uploaded.filename == "":
            flash("No file selected.", "error")
            return redirect(request.url)

        filename = secure_filename(uploaded.filename)

        if not _allowed_file(filename):
            flash("File type not allowed.", "error")
            return redirect(request.url)

        # Parse and validate record ID
        try:
            record_id = int(record_id_str)
        except (ValueError, TypeError):
            flash("Please select a valid registered record.", "error")
            return redirect(request.url)

        reference = db.get_registered_file(record_id)

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name
                uploaded.save(tmp_path)

            file_size = os.path.getsize(tmp_path)

            with open(tmp_path, "rb") as fh:
                current_hash = hash_utils.compute_hash_from_stream(fh)

        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)

        if reference is None:
            result = "UNKNOWN"
            original_hash = ""
            ref_size = 0
            # Use None so the FOREIGN KEY constraint is not violated
            db_registered_id = None
        else:
            original_hash = reference["sha256_hash"]
            ref_size = reference["file_size"]
            result = "UNCHANGED" if hash_utils.hashes_match(original_hash, current_hash) else "MODIFIED"
            db_registered_id = record_id

        # Record this verification event (never overwrites reference hash)
        db.add_verification(
            registered_id=db_registered_id,
            filename=filename,
            original_hash=original_hash,
            current_hash=current_hash,
            file_size=file_size,
            result=result,
        )

        return render_template(
            "verify.html",
            registered_files=registered_files,
            result=result,
            filename=filename,
            record_id=record_id,
            original_hash=original_hash,
            current_hash=current_hash,
            file_size=file_size,
            ref_size=ref_size,
            reference=reference,
            verified=True,
        )

    return render_template(
        "verify.html",
        registered_files=registered_files,
        verified=False,
    )


# ---------------------------------------------------------------------------
# Verification History
# ---------------------------------------------------------------------------

@app.route("/history")
def history():
    result_filter = request.args.get("filter", "").strip().upper() or None
    if result_filter not in (None, "UNCHANGED", "MODIFIED", "UNKNOWN"):
        result_filter = None
    records = db.get_all_verifications(result_filter)
    return render_template(
        "history.html",
        records=records,
        active_filter=result_filter or "ALL",
    )


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

@app.route("/export/csv")
def export_csv():
    result_filter = request.args.get("filter", "").strip().upper() or None
    if result_filter not in (None, "UNCHANGED", "MODIFIED", "UNKNOWN"):
        result_filter = None

    records = db.get_all_verifications(result_filter)

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow(
        [
            "History ID",
            "Registered Record ID",
            "Filename",
            "Verified At (UTC)",
            "Reference SHA-256",
            "Current SHA-256",
            "File Size (bytes)",
            "Result",
        ]
    )
    for row in records:
        writer.writerow(
            [
                row["id"],
                row["registered_id"],
                row["filename"],
                row["verified_at"],
                row["original_hash"],
                row["current_hash"],
                row["file_size"],
                row["result"],
            ]
        )

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=verification_report.csv"
        },
    )


# ---------------------------------------------------------------------------
# API: list registered files (used by the verify page's dynamic dropdown)
# ---------------------------------------------------------------------------

@app.route("/api/registered")
def api_registered():
    files = db.get_all_registered_files()
    return jsonify(
        [
            {
                "id": r["id"],
                "filename": r["filename"],
                "file_size": r["file_size"],
                "sha256_hash": r["sha256_hash"],
                "registered_at": r["registered_at"],
            }
            for r in files
        ]
    )


# ---------------------------------------------------------------------------
# Delete a registered record (with confirmation from the client)
# ---------------------------------------------------------------------------

@app.route("/registered/<int:record_id>/delete", methods=["POST"])
def delete_record(record_id):
    deleted = db.delete_registered_file(record_id)
    if deleted:
        flash(f"Record {record_id} deleted successfully.", "success")
    else:
        flash(f"Record {record_id} not found.", "error")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Security Information
# ---------------------------------------------------------------------------

@app.route("/security-info")
def security_info():
    return render_template("security_info.html")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Debug mode is disabled; set to True only during development.
    app.run(host="127.0.0.1", port=5000, debug=True)
