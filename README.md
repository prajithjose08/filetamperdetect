# File Tampering Detector

A beginner-friendly cybersecurity mini-project that detects whether a file has
been modified by comparing its **SHA-256 cryptographic hash** with a previously
saved reference record stored in SQLite.

---

## What It Does

| Feature | Details |
|---|---|
| File Registration | Upload any file; its SHA-256 hash + metadata are saved as a trusted reference |
| Integrity Verification | Re-upload the file later; the system compares hashes and reports UNCHANGED / MODIFIED / UNKNOWN |
| Verification History | Every check is persisted in SQLite with timestamps and results |
| CSV Export | Download all history records as a properly-escaped CSV |
| Security Info Page | Plain-English explanation of SHA-256, hashing vs encryption, and limitations |

No paid APIs, no cloud services, no database server — everything runs locally.

---

## Technology Stack

- **Python 3.10+** with **Flask** (web framework)
- **hashlib** (built-in) — SHA-256 hashing
- **SQLite** (built-in) — persistent storage
- **HTML5 / CSS3 / JavaScript** — dark cybersecurity-themed UI

---

## Project Structure

```
FileTamperingDetector/
├── app.py              ← Flask routes and application entry point
├── hash_utils.py       ← SHA-256 hashing functions
├── database.py         ← All SQLite queries (parameterised, safe)
├── requirements.txt    ← Python dependencies
├── README.md           ← This file
├── templates/
│   ├── base.html       ← Shared layout (sidebar, flash messages)
│   ├── index.html      ← Dashboard with stats and recent activity
│   ├── register.html   ← File registration form and result
│   ├── verify.html     ← File verification form and result
│   ├── history.html    ← Filterable verification history table
│   ├── security_info.html ← Educational security information page
│   ├── 404.html        ← Not-found error page
│   └── 500.html        ← Server error page
├── static/
│   ├── css/style.css   ← All styling (dark theme, responsive)
│   └── js/script.js    ← Drag-and-drop, copy, flash auto-dismiss
├── instance/
│   └── file_integrity.db  ← Created automatically on first run
└── tests/
    └── test_hash_utils.py ← Automated unit tests
```

---

## Quick Start (Windows / VS Code)

### 1. Open the project folder in VS Code

```
File → Open Folder → select FileTamperingDetector
```

### 2. Create and activate a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

> If you see a script-execution error, run this first:
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Run the application

```powershell
python app.py
```

### 5. Open your browser

```
http://127.0.0.1:5000
```

---

## Running Tests

```powershell
python -m pytest tests/ -v
```

---

## Demo Sequence (College Presentation)

1. **Dashboard** — show the stat cards (all zeros at start).
2. **Register** — upload any `.txt` file; show the Record ID and SHA-256 hash.
3. **Verify (clean)** — upload the *same unchanged* file; point out **FILE UNCHANGED** and matching hashes.
4. **Tamper** — open the file in Notepad, add one space, save.
5. **Verify (modified)** — upload the edited file; show **FILE MODIFIED** and the two different hashes side by side.
6. **History** — show the two entries; use the filter buttons.
7. **Export CSV** — download and open in Excel.
8. **Security Info** — walk through the SHA-256 explanation and limitations table.

---

## Security Notes & Limitations

- The SQLite database (`instance/file_integrity.db`) is stored locally.
  Anyone with filesystem write access can modify it, which would defeat the integrity check.
  This application is **educational** — it does not provide a digitally signed audit trail.

- The upload limit is 50 MiB by default (configurable in `app.py`).

- File-type validation is extension-based; it is not a substitute for a full malware scanner.

- SHA-256 detects *whether* a file changed but cannot identify *who* changed it or *which bytes* differ.

- To harden this for real use: add OS-level database access controls, use digital signatures
  (e.g., sign the hash with a private key), or publish hashes to an immutable log.

---

## License

MIT — free to use, modify, and share for educational purposes.
