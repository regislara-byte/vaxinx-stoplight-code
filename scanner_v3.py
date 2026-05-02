"""
🛡️ VAXINX Stoplight Code Scanner — v3.0-VAULT
Defensive educational scanner. Does NOT execute scanned files.

New in v3.0:
  - YARA rule engine (loads all .yar/.yara files from rules/ directory)
  - Flask REST API server with live scan endpoint + SSE streaming
  - /api/scan      POST  { "path": "..." }  → triggers scan, streams progress
  - /api/report    GET                      → latest scan report
  - /api/status    GET                      → scanner health
  - /api/rules     GET                      → loaded YARA rules list
  - Web dashboard served at /

Retained from v2.0:
  - Entropy analysis, magic byte signatures, content scanning
  - Score normalization, hash deduplication
  - Argparse CLI, rotating logs, Fernet quarantine vault
"""

import os
import sys
import math
import json
import struct
import hashlib
import logging
import zipfile
import argparse
import threading
import queue
import time
from pathlib import Path
from datetime import datetime
from collections import Counter
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet

# ── Optional YARA import (graceful fallback if not installed) ────────────────
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# ── Optional Flask import ────────────────────────────────────────────────────
try:
    from flask import Flask, jsonify, request, Response, send_from_directory
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# ─── Version ─────────────────────────────────────────────────────────────────
APP_VERSION = "3.0-VAULT"

# ─── Default Paths ───────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).resolve().parent
SCAN_TARGET    = BASE_DIR / "test_lab"
REPORT_DIR     = BASE_DIR / "reports"
QUARANTINE_DIR = BASE_DIR / "quarantine"
LOG_DIR        = BASE_DIR / "logs"
KEY_DIR        = BASE_DIR / ".vault_keys"
RULES_DIR      = BASE_DIR / "rules"
REPORT_FILE    = REPORT_DIR / "scan_report.json"
KEY_FILE       = KEY_DIR / "vault.key"
LOG_FILE       = LOG_DIR / "vaxinx.log"
DASHBOARD_DIR  = BASE_DIR / "dashboard"

# ─── Scanner Config ───────────────────────────────────────────────────────────
QUARANTINE_HIGH_RISK      = True
SECURE_OVERWRITE_ORIGINAL = True
OVERWRITE_PASSES          = 3
SCAN_TEXT_CONTENT         = True
MAX_TEXT_SCAN_SIZE        = 1_000_000
ENTROPY_THRESHOLD         = 7.2
ARCHIVE_NEST_WARN_DEPTH   = 3

# ─── Extension Sets ───────────────────────────────────────────────────────────
HIGH_RISK_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".ps1", ".jar",
    ".msi", ".dll", ".com", ".hta", ".wsf", ".pif", ".reg",
}
MEDIUM_RISK_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm", ".iso", ".cab",
}
SCRIPT_EXTENSIONS  = {".bat", ".cmd", ".vbs", ".js", ".ps1", ".wsf", ".hta"}
MACRO_EXTENSIONS   = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".cab"}
PE_EXTENSIONS      = {".exe", ".dll", ".scr", ".msi", ".com", ".pif"}
HARMLESS_LOOK_EXTS = {".txt", ".jpg", ".png", ".pdf", ".doc", ".mp3", ".mp4"}
TEXT_EXTENSIONS    = {
    ".txt", ".py", ".js", ".ts", ".html", ".htm", ".xml", ".csv",
    ".log", ".ini", ".cfg", ".conf", ".sh", ".bat", ".cmd", ".ps1",
    ".vbs", ".php", ".rb", ".pl",
}

# ─── Keyword Lists ────────────────────────────────────────────────────────────
SUSPICIOUS_FILENAME_KEYWORDS = [
    "password", "credential", "token", "secret", "payload", "hack",
    "malware", "ransom", "encrypt", "decrypt", "keylogger", "stealth",
    "backdoor", "rootkit", "spy", "tracker", "worm", "love-letter",
    "free", "crack", "patch", "activator", "invoice", "urgent",
    "prize", "update", "security-alert",
]
SUSPICIOUS_CONTENT_KEYWORDS = [
    "cmd.exe", "powershell", "base64", "eval(", "exec(", "subprocess",
    "os.system", "shell=True", "wget ", "curl ", "net user", "reg add",
    "schtasks", "certutil", "invoke-expression", "iex(", "bypass",
    "hidden", "downloadstring", "webclient", "invoke-webrequest",
    "createobject", "wscript.shell", "cscript",
]
MALWARE_SIGNATURE_HINTS = {
    "Virus":      ["infect", "replicate", "modify", "spread"],
    "Trojan":     ["free", "crack", "patch", "activator", "game", "prize", "invoice", "love-letter"],
    "Worm":       ["worm", "replicate", "network", "share"],
    "Ransomware": ["ransom", "encrypt", "decrypt", "locked", "payment"],
    "Spyware":    ["spy", "tracker", "keylogger", "credential", "password", "token"],
    "Adware":     ["adware", "popup", "ads"],
    "Scareware":  ["urgent", "security-alert", "warning", "infected"],
    "Backdoor":   ["backdoor", "remote", "shell"],
    "Rootkit":    ["rootkit", "stealth", "kernel"],
}
BYTE_SIGNATURES = [
    ("PE executable (MZ header)",      0,    b"MZ"),
    ("ELF executable",                 0,    b"\x7fELF"),
    ("PDF document",                   0,    b"%PDF"),
    ("ZIP archive",                    0,    b"PK\x03\x04"),
    ("RAR archive",                    0,    b"Rar!"),
    ("7-Zip archive",                  0,    b"7z\xbc\xaf\x27\x1c"),
    ("Java class file",                0,    b"\xca\xfe\xba\xbe"),
    ("Mach-O binary (32-bit)",         0,    b"\xce\xfa\xed\xfe"),
    ("Mach-O binary (64-bit)",         0,    b"\xcf\xfa\xed\xfe"),
    ("MS Office OLE2 compound",        0,    b"\xd0\xcf\x11\xe0"),
    ("Shebang script",                 0,    b"#!"),
    ("PowerShell encoded command",     None, b"EncodedCommand"),
    ("Base64-encoded PE header",       None, b"TVqQAAMAAAAEAAAA"),
    ("VBScript CreateObject pattern",  None, b"CreateObject"),
    ("Certutil decode pattern",        None, b"certutil"),
]


# ─── Logging ──────────────────────────────────────────────────────────────────
def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("vaxinx")
    logger.setLevel(logging.DEBUG)
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(ch)
    return logger

log = setup_logging()


# ─── Directory Setup ──────────────────────────────────────────────────────────
def ensure_dirs():
    for d in [SCAN_TARGET, REPORT_DIR, QUARANTINE_DIR, LOG_DIR, KEY_DIR, RULES_DIR, DASHBOARD_DIR]:
        d.mkdir(parents=True, exist_ok=True)


# ─── Key Management ───────────────────────────────────────────────────────────
def load_or_create_key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    try:
        KEY_FILE.chmod(0o600)
    except Exception:
        pass
    log.info(f"[KEY] Vault key created: {KEY_FILE}")
    return key

def encrypt_data(data: bytes) -> bytes:
    return Fernet(load_or_create_key()).encrypt(data)


# ─── YARA Engine ─────────────────────────────────────────────────────────────
_yara_rules = None
_yara_rules_meta: list[dict] = []

def load_yara_rules(rules_dir: Path = RULES_DIR) -> bool:
    global _yara_rules, _yara_rules_meta
    if not YARA_AVAILABLE:
        log.warning("[YARA] yara-python not installed. Run: pip install yara-python")
        return False
    rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
    if not rule_files:
        log.warning(f"[YARA] No rule files found in {rules_dir}")
        return False
    try:
        filepaths = {f.stem: str(f) for f in rule_files}
        _yara_rules = yara.compile(filepaths=filepaths)
        _yara_rules_meta = [{"file": f.name, "path": str(f)} for f in rule_files]
        log.info(f"[YARA] Loaded {len(rule_files)} rule file(s): {[f.name for f in rule_files]}")
        return True
    except Exception as err:
        log.error(f"[YARA] Failed to compile rules: {err}")
        return False

def yara_scan(path: Path) -> list[dict]:
    """Run YARA rules against a file. Returns list of match dicts."""
    if not YARA_AVAILABLE or _yara_rules is None:
        return []
    try:
        matches = _yara_rules.match(str(path))
        return [
            {
                "rule":        m.rule,
                "namespace":   m.namespace,
                "tags":        list(m.tags),
                "severity":    m.meta.get("severity", "UNKNOWN"),
                "description": m.meta.get("description", ""),
                "family":      m.meta.get("family", "Unknown"),
                "strings":     [
                    {"identifier": s.identifier, "offset": s.instances[0].offset if s.instances else 0}
                    for s in m.strings
                ],
            }
            for m in matches
        ]
    except Exception as err:
        log.debug(f"[YARA] Error scanning {path.name}: {err}")
        return []


# ─── Core Analysis Helpers ────────────────────────────────────────────────────
def overwrite_file(path: Path, passes: int = OVERWRITE_PASSES) -> bool:
    try:
        if not path.exists(): return False
        size = path.stat().st_size
        if size == 0: return True
        with open(path, "r+b") as fh:
            for _ in range(passes):
                fh.seek(0); fh.write(os.urandom(size))
                fh.flush(); os.fsync(fh.fileno())
        return True
    except PermissionError:
        log.warning(f"[OVERWRITE] File locked: {path}")
        return False
    except Exception as err:
        log.warning(f"[OVERWRITE] Failed: {err}")
        return False

def sha256_hash(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""): h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unreadable"

def file_entropy(path: Path, sample: int = 65536) -> float:
    try:
        with open(path, "rb") as fh: data = fh.read(sample)
        if not data: return 0.0
        counts = Counter(data); total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())
    except Exception:
        return 0.0

def read_bytes(path: Path, size: int = 4096) -> bytes:
    try:
        with open(path, "rb") as fh: return fh.read(size)
    except Exception:
        return b""

def check_byte_signatures(header: bytes) -> list[str]:
    return [
        label for label, offset, pat in BYTE_SIGNATURES
        if (header[offset:offset+len(pat)] == pat if offset is not None else pat in header)
    ]

def scan_text_content(path: Path) -> list[str]:
    hits = []
    try:
        if path.stat().st_size > MAX_TEXT_SCAN_SIZE:
            return ["Text content scan skipped: exceeds size limit"]
        content = path.read_text(encoding="utf-8", errors="ignore").lower()
        for kw in SUSPICIOUS_CONTENT_KEYWORDS:
            if kw.lower() in content:
                hits.append(f"Suspicious content keyword: '{kw}'")
    except Exception:
        pass
    return hits

def check_archive_nesting(path: Path, depth: int = 0) -> int:
    if depth > 6: return depth
    try:
        if not zipfile.is_zipfile(path): return depth
        import io
        with zipfile.ZipFile(path, "r") as zf:
            max_depth = depth
            for name in zf.namelist():
                if name.lower().endswith(".zip"):
                    try:
                        tmp = Path(f"/tmp/_vaxinx_nest_{depth}.zip")
                        tmp.write_bytes(io.BytesIO(zf.read(name)).read())
                        max_depth = max(max_depth, check_archive_nesting(tmp, depth + 1))
                        tmp.unlink(missing_ok=True)
                    except Exception:
                        pass
            return max_depth
    except Exception:
        return depth

def classify_stoplight(score: int) -> str:
    if score >= 70: return "RED"
    if score >= 30: return "YELLOW"
    return "GREEN"

def classify_file_type(suffixes: list) -> str:
    if any(e in PE_EXTENSIONS      for e in suffixes): return "PE_OR_WINDOWS_EXECUTABLE"
    if any(e in SCRIPT_EXTENSIONS  for e in suffixes): return "SCRIPT_EXECUTION_CAPABLE"
    if any(e in MACRO_EXTENSIONS   for e in suffixes): return "MACRO_DOCUMENT"
    if any(e in ARCHIVE_EXTENSIONS for e in suffixes): return "ARCHIVE_OR_CONTAINER"
    if any(e in HIGH_RISK_EXTENSIONS for e in suffixes): return "EXECUTION_CAPABLE"
    return "STANDARD_FILE"

def has_any(text: str, words: list) -> bool:
    return any(w in text for w in words)

def detect_human_error(filename: str) -> str:
    name = filename.lower()
    if any(w in name for w in ["bank", "login", "verify", "account"]): return "PHISHING_LURE"
    if "update" in name: return "FAKE_UPDATE"
    if any(w in name for w in ["password", "wifi"]): return "PASSWORD_SHARING_RISK"
    if any(p in name for p in [".pdf.exe", ".txt.vbs", ".doc.exe"]): return "DISGUISED_ATTACHMENT"
    return "NONE"

def infer_malware_types(filename: str, suffixes: list, reasons: list) -> list:
    evidence = f"{filename.lower()} {' '.join(reasons).lower()} {' '.join(suffixes)}"
    guesses = []
    if len(suffixes) > 1 and suffixes[-1] in HIGH_RISK_EXTENSIONS:
        guesses.append("Trojan / Disguised executable")
    if any(e in SCRIPT_EXTENSIONS for e in suffixes): guesses.append("Script-based malware risk")
    if any(e in MACRO_EXTENSIONS  for e in suffixes): guesses.append("Macro malware risk")
    for family, keywords in MALWARE_SIGNATURE_HINTS.items():
        if has_any(evidence, keywords): guesses.append(f"{family} behavior hint")
    if any(e in PE_EXTENSIONS for e in suffixes): guesses.append("Virus/Trojan executable risk")
    return sorted(set(guesses)) or ["No malware family hint detected"]

def quarantine_file(path: Path) -> dict:
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        locked = f"[QUARANTINED]_{ts}_{path.name}.vxlocked"
        dest = QUARANTINE_DIR / locked
        c = 1
        while dest.exists():
            locked = f"[QUARANTINED]_{ts}_{c}_{path.name}.vxlocked"
            dest = QUARANTINE_DIR / locked; c += 1
        dest.write_bytes(encrypt_data(path.read_bytes()))
        ok = overwrite_file(path) if SECURE_OVERWRITE_ORIGINAL else False
        path.unlink(missing_ok=True)
        log.warning(f"[QUARANTINE] {path.name} → {dest.name}")
        return {"status": "QUARANTINED", "quarantined_as": str(dest),
                "message": "Encrypted & moved to Vault", "encrypted": True,
                "secure_overwrite_attempted": SECURE_OVERWRITE_ORIGINAL,
                "secure_overwrite_success": ok, "vault_extension": ".vxlocked"}
    except Exception as err:
        log.error(f"[QUARANTINE FAILED] {path}: {err}")
        return {"status": "FAILED", "quarantined_as": None, "message": str(err),
                "encrypted": False, "secure_overwrite_attempted": SECURE_OVERWRITE_ORIGINAL,
                "secure_overwrite_success": False, "vault_extension": None}


# ─── Core File Analyzer ───────────────────────────────────────────────────────
def analyze_file(path: Path, seen_hashes: set | None = None, progress_cb=None) -> dict | None:
    reasons: list[str] = []
    scored_categories: set[str] = set()

    def add_score(cat: str, pts: int, reason: str) -> int:
        reasons.append(reason)
        if cat not in scored_categories:
            scored_categories.add(cat); return pts
        return 0

    score = 0
    suffixes  = [s.lower() for s in path.suffixes]
    filename  = path.name.lower()
    file_type = classify_file_type(suffixes)

    file_hash = sha256_hash(path)
    if seen_hashes is not None:
        if file_hash in seen_hashes and file_hash != "unreadable":
            return None
        seen_hashes.add(file_hash)

    # Extension scoring (take max, don't stack)
    ext_score = 0
    for ext in suffixes:
        if ext in PE_EXTENSIONS:      ext_score = max(ext_score, 45); reasons.append(f"PE extension: {ext}")
        elif ext in SCRIPT_EXTENSIONS: ext_score = max(ext_score, 45); reasons.append(f"Script extension: {ext}")
        elif ext in MACRO_EXTENSIONS:  ext_score = max(ext_score, 35); reasons.append(f"Macro document: {ext}")
        elif ext in ARCHIVE_EXTENSIONS: ext_score = max(ext_score, 20); reasons.append(f"Archive: {ext}")
        elif ext in HIGH_RISK_EXTENSIONS: ext_score = max(ext_score, 35); reasons.append(f"High-risk extension: {ext}")
        elif ext in MEDIUM_RISK_EXTENSIONS: ext_score = max(ext_score, 20); reasons.append(f"Medium-risk extension: {ext}")
    score += ext_score

    if len(suffixes) > 1:
        score += add_score("multi_ext", 25, f"Multiple extensions: {' '.join(suffixes)}")
    if suffixes and suffixes[-1] in HIGH_RISK_EXTENSIONS and any(e in HARMLESS_LOOK_EXTS for e in suffixes[:-1]):
        score += add_score("disguise", 35, "Extension disguise detected")

    # Magic bytes
    header = read_bytes(path)
    sig_matches = check_byte_signatures(header)
    for sig in sig_matches:
        if any(k in sig for k in ("PE executable", "ELF", "Mach-O", "Java class")):
            score += add_score("magic_exec", 45, f"Magic bytes: {sig}")
        elif any(k in sig for k in ("PowerShell", "CreateObject", "Certutil")):
            score += add_score("magic_script", 40, f"Byte pattern: {sig}")
        elif "base64" in sig.lower():
            score += add_score("base64_magic", 35, f"Suspicious pattern: {sig}")
        else:
            reasons.append(f"File signature: {sig}")

    # Signature mismatch
    if sig_matches and suffixes:
        last_ext = suffixes[-1]
        if any("PE executable" in s or "ELF" in s for s in sig_matches):
            if last_ext not in PE_EXTENSIONS | SCRIPT_EXTENSIONS:
                score += add_score("sig_mismatch", 40, f"Sig mismatch: PE bytes but extension is '{last_ext}'")

    # Entropy
    entropy = file_entropy(path)
    if entropy >= ENTROPY_THRESHOLD and any(e in PE_EXTENSIONS | SCRIPT_EXTENSIONS for e in suffixes):
        score += add_score("entropy", 30, f"High entropy ({entropy:.2f}) — packed/encrypted?")
    elif entropy >= ENTROPY_THRESHOLD:
        reasons.append(f"Elevated entropy ({entropy:.2f} bits/byte)")

    # Filename keywords
    for kw in SUSPICIOUS_FILENAME_KEYWORDS:
        if kw in filename:
            reasons.append(f"Suspicious keyword: '{kw}'")
            score += 12

    # Human error
    human_error = detect_human_error(path.name)
    if human_error != "NONE":
        score += add_score("social_eng", 15, f"Social engineering: {human_error}")

    # Content scan
    content_hits: list[str] = []
    if SCAN_TEXT_CONTENT and suffixes and suffixes[-1] in TEXT_EXTENSIONS:
        content_hits = scan_text_content(path)
        for hit in content_hits:
            score += add_score(f"content_{hit[:20]}", 20, hit)

    # YARA scan
    yara_matches = yara_scan(path)
    for match in yara_matches:
        sev = match.get("severity", "MEDIUM")
        pts = {"CRITICAL": 50, "HIGH": 35, "MEDIUM": 20, "LOW": 10}.get(sev, 20)
        score += add_score(f"yara_{match['rule']}", pts,
                           f"YARA: {match['rule']} [{sev}] — {match.get('description','')}")

    # Archive nesting
    archive_depth = 0
    if suffixes and suffixes[-1] == ".zip":
        archive_depth = check_archive_nesting(path)
        if archive_depth >= ARCHIVE_NEST_WARN_DEPTH:
            score += add_score("zip_bomb", 30, f"Deep archive nesting ({archive_depth} levels)")

    # Size
    try:   size_bytes = path.stat().st_size
    except Exception: size_bytes = 0; score += 10; reasons.append("Could not read file size")
    if size_bytes == 0: reasons.append("Empty file"); score += 5
    elif size_bytes > 50_000_000: reasons.append("Large file >50MB"); score += 10

    score = min(score, 100)
    stoplight = classify_stoplight(score)

    result = {
        "original_path":    str(path),
        "name":             path.name,
        "extensions":       suffixes,
        "file_type":        file_type,
        "size_bytes":       size_bytes,
        "sha256":           file_hash,
        "entropy":          round(entropy, 4),
        "score":            score,
        "stoplight":        stoplight,
        "decision":         {"GREEN": "ALLOW", "YELLOW": "INSPECT", "RED": "QUARANTINE"}[stoplight],
        "human_error_risk": human_error,
        "byte_signatures":  sig_matches,
        "content_hits":     content_hits,
        "yara_matches":     yara_matches,
        "archive_depth":    archive_depth,
        "malware_hints":    infer_malware_types(filename, suffixes, reasons),
        "reasons":          reasons or ["No suspicious indicators detected"],
        "quarantine": {
            "status": "NOT_REQUIRED", "quarantined_as": None,
            "message": "No action needed", "encrypted": False,
            "secure_overwrite_attempted": False, "secure_overwrite_success": False,
            "vault_extension": None,
        },
    }

    if QUARANTINE_HIGH_RISK and stoplight == "RED":
        result["quarantine"] = quarantine_file(path)

    if progress_cb:
        progress_cb(result)

    return result


# ─── Folder Scanner ───────────────────────────────────────────────────────────
def scan_folder(folder: Path, progress_cb=None) -> dict:
    results = []
    seen_hashes: set[str] = set()
    skipped = 0

    for root, _, filenames in os.walk(folder):
        if "quarantine" in Path(root).parts: continue
        for filename in filenames:
            path = Path(root) / filename
            r = analyze_file(path, seen_hashes, progress_cb)
            if r is None: skipped += 1
            else:
                results.append(r)
                log.debug(f"[SCAN] {r['stoplight']:6s} score={r['score']:3d} | {path.name}")

    summary = {
        "total_files":              len(results),
        "skipped_duplicates":       skipped,
        "green":                    sum(1 for r in results if r["stoplight"] == "GREEN"),
        "yellow":                   sum(1 for r in results if r["stoplight"] == "YELLOW"),
        "red":                      sum(1 for r in results if r["stoplight"] == "RED"),
        "quarantined":              sum(1 for r in results if r["quarantine"]["status"] == "QUARANTINED"),
        "high_entropy_files":       sum(1 for r in results if r.get("entropy", 0) >= ENTROPY_THRESHOLD),
        "yara_hits":                sum(1 for r in results if r.get("yara_matches")),
        "content_hits_total":       sum(len(r.get("content_hits", [])) for r in results),
    }

    return {
        "scanner":    "VAXINX Stoplight Code Scanner",
        "version":    APP_VERSION,
        "scan_time":  datetime.now().isoformat(timespec="seconds"),
        "target":     str(folder),
        "yara_rules": _yara_rules_meta,
        "summary":    summary,
        "results":    results,
    }


# ─── Flask API Server ─────────────────────────────────────────────────────────
_latest_report: dict = {}
_scan_lock = threading.Lock()
_sse_queues: list[queue.Queue] = []

def create_app() -> "Flask":
    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask not installed. Run: pip install flask flask-cors")

    app = Flask(__name__, static_folder=str(DASHBOARD_DIR))
    CORS(app)

    @app.route("/")
    def index():
        return send_from_directory(str(DASHBOARD_DIR), "index.html")

    @app.route("/api/status")
    def status():
        return jsonify({
            "status":         "online",
            "version":        APP_VERSION,
            "yara_available": YARA_AVAILABLE,
            "yara_rules":     _yara_rules_meta,
            "scan_target":    str(SCAN_TARGET),
            "time":           datetime.now().isoformat(timespec="seconds"),
        })

    @app.route("/api/rules")
    def rules():
        return jsonify({"rules": _yara_rules_meta, "yara_available": YARA_AVAILABLE})

    @app.route("/api/report")
    def report():
        if _latest_report:
            return jsonify(_latest_report)
        if REPORT_FILE.exists():
            with open(REPORT_FILE) as f:
                return jsonify(json.load(f))
        return jsonify({"error": "No report available yet"}), 404

    @app.route("/api/scan", methods=["POST"])
    def scan():
        global _latest_report
        data = request.get_json(silent=True) or {}
        target_path = Path(data.get("path", str(SCAN_TARGET)))
        dry_run     = data.get("dry_run", False)

        if not target_path.exists():
            return jsonify({"error": f"Path not found: {target_path}"}), 400

        if not _scan_lock.acquire(blocking=False):
            return jsonify({"error": "Scan already in progress"}), 409

        def do_scan():
            global _latest_report, QUARANTINE_HIGH_RISK
            try:
                saved_qhr = QUARANTINE_HIGH_RISK
                if dry_run: QUARANTINE_HIGH_RISK = False

                def on_file(result):
                    event = json.dumps({"type": "file", "data": result})
                    for q in list(_sse_queues):
                        try: q.put_nowait(event)
                        except Exception: pass

                rpt = scan_folder(target_path, progress_cb=on_file)
                _latest_report = rpt

                with open(REPORT_FILE, "w") as f:
                    json.dump(rpt, f, indent=2)

                done_event = json.dumps({"type": "done", "data": rpt["summary"]})
                for q in list(_sse_queues):
                    try: q.put_nowait(done_event)
                    except Exception: pass

                if dry_run: QUARANTINE_HIGH_RISK = saved_qhr
            finally:
                _scan_lock.release()

        t = threading.Thread(target=do_scan, daemon=True)
        t.start()
        return jsonify({"status": "started", "target": str(target_path), "dry_run": dry_run})

    @app.route("/api/stream")
    def stream():
        """SSE endpoint — clients subscribe to get live scan events."""
        q: queue.Queue = queue.Queue(maxsize=500)
        _sse_queues.append(q)

        def event_stream():
            try:
                yield "data: {\"type\":\"connected\"}\n\n"
                while True:
                    try:
                        msg = q.get(timeout=30)
                        yield f"data: {msg}\n\n"
                        if json.loads(msg).get("type") == "done":
                            break
                    except queue.Empty:
                        yield ": keepalive\n\n"
            finally:
                _sse_queues.remove(q)

        return Response(event_stream(),
                        mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app


# ─── CLI ──────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description=f"🛡️ VAXINX v{APP_VERSION}")
    p.add_argument("target", nargs="?", default=str(SCAN_TARGET))
    p.add_argument("--report",            default=str(REPORT_FILE))
    p.add_argument("--rules-dir",         default=str(RULES_DIR))
    p.add_argument("--no-quarantine",     action="store_true")
    p.add_argument("--no-content-scan",   action="store_true")
    p.add_argument("--entropy-threshold", type=float, default=ENTROPY_THRESHOLD)
    p.add_argument("--serve",             action="store_true", help="Start web dashboard server")
    p.add_argument("--host",              default="127.0.0.1")
    p.add_argument("--port",              type=int, default=5000)
    p.add_argument("--debug",             action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    global QUARANTINE_HIGH_RISK, SCAN_TEXT_CONTENT, ENTROPY_THRESHOLD, RULES_DIR

    if args.no_quarantine:   QUARANTINE_HIGH_RISK = False
    if args.no_content_scan: SCAN_TEXT_CONTENT    = False
    ENTROPY_THRESHOLD = args.entropy_threshold
    RULES_DIR         = Path(args.rules_dir)

    ensure_dirs()
    load_yara_rules(RULES_DIR)

    if args.serve:
        if not FLASK_AVAILABLE:
            log.error("Flask not installed. Run: pip install flask flask-cors")
            sys.exit(1)
        log.info(f"🌐 Starting VAXINX dashboard at http://{args.host}:{args.port}")
        app = create_app()
        app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
        return

    # CLI scan mode
    target = Path(args.target)
    if not target.exists():
        log.error(f"Target not found: {target}"); sys.exit(1)

    log.info(f"🛡️ VAXINX v{APP_VERSION} — scanning {target}")
    report = scan_folder(target)

    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)

    log.info(f"\n{'─'*40}\n🛡️  Done — {args.report}")
    log.info(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
