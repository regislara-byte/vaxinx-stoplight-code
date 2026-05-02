# 🛡️ VAXINX Stoplight Scanner — v3.0-VAULT

> **think_like_attacker → act_like_defender**

A **Python + JSON + HTML hybrid cybersecurity tool** that simulates real-world defensive analysis using a **Stoplight Risk Model (RED / YELLOW / GREEN)**. Part of the **VAXINX Protocol™** ecosystem — a reverse-learning system where you build first, then map to theory.

**Live Dashboard:** [regislara-byte.github.io/vaxinx-cert-dashboard](https://regislara-byte.github.io/vaxinx-cert-dashboard/)  
**Credly Profile:** [credly.com/users/regis-lara](https://www.credly.com/users/regis-lara)  
**GitHub:** [github.com/regislara-byte](https://github.com/regislara-byte)

---

## ⚡ What's New in v3.0-VAULT

| Feature | Details |
|---|---|
| 🤖 YARA Rule Engine | Loads all `.yar` / `.yara` files from `rules/` directory |
| 🌐 Flask REST API | Live scan endpoint + SSE streaming at `http://127.0.0.1:5000` |
| 📡 SSE Live Feed | `/api/stream` — real-time file-by-file scan events |
| 🎨 Upgraded Dashboard | Aligned with VAXINX cert portfolio — Doppio guardian, credential cards, achievement grid |
| 🔐 Quarantine Vault | Fernet-encrypted `.vxlocked` files with secure overwrite |
| 🧾 Cisco Certifications | 7 verified achievements now reflected in the dashboard |

---

## 🚦 Stoplight Risk Model

| Signal | Decision | Action |
|---|---|---|
| 🟢 **GREEN** | Allow | Safe — no threat indicators detected |
| 🟡 **YELLOW** | Inspect | Suspicious — manual review required |
| 🔴 **RED** | Quarantine | High risk — encrypted into `.vxlocked` vault |

---

## 🧠 Core System Modules

```txt
VAXINX_SYSTEM = {
  "file_scanner":   "Python-based threat detection engine",
  "stoplight_logic":"RED / YELLOW / GREEN classification",
  "yara_engine":    "Rule-based pattern matching (v3.0 new)",
  "flask_api":      "REST API + SSE live stream (v3.0 new)",
  "siem_lite":      "Log ingestion + pattern analysis (planned)",
  "dlp_module":     "Data loss prevention checks (planned)",
  "json_reports":   "Structured audit output",
  "html_dashboard": "Visual cyber intelligence UI + Doppio"
}
```

---

## 🔍 Detection Engine

### File Analysis
- Extension risk classification (HIGH / MEDIUM / HARMLESS)
- Magic byte signature scanning (PE, ELF, ZIP, RAR, Java, Mach-O, OLE2...)
- Entropy analysis — detects packed / encrypted payloads
- Suspicious filename keyword detection
- Social engineering pattern detection
- Malware behavior hints (Trojan, Ransomware, Spyware, Backdoor, Rootkit...)

### Advanced Detection
- **YARA rule engine** — loads `.yar` / `.yara` files from `rules/`
- Content scanning (scripts, commands, encoded payloads)
- Archive nesting detection (zip bombs)
- Hash-based deduplication (SHA-256)

### Quarantine Vault
- Triggered automatically on RED decisions
- Files encrypted with **Fernet** symmetric encryption
- Stored as `.vxlocked` in `/quarantine`
- Optional 3-pass secure overwrite of original

---

## 📁 Project Structure

```txt
vaxinx-stoplight-code/
├── scanner_v3.py           ← Main engine (CLI + Flask API)
├── restore_quarantine.py   ← Decrypt and restore vaulted files
├── vaxinx_crypto.py        ← Fernet key management
├── app.js                  ← Dashboard JS (legacy static mode)
├── style.css               ← Legacy stylesheet
├── run_lab.bat             ← Windows quick-launch
├── README.md
│
├── dashboard/
│   ├── index.html          ← Upgraded dashboard (v3.0 aligned)
│   └── Vaxinx_Doppio.gif   ← Guardian mascot asset
│
├── test_lab/               ← Drop files here to scan
├── quarantine/             ← Encrypted .vxlocked vault
├── reports/                ← scan_report.json output
├── logs/                   ← Rotating vaxinx.log
├── rules/                  ← YARA rule files (.yar / .yara)
└── .vault_keys/            ← ⚠️ NEVER COMMIT — encryption keys
```

---

## ▶️ How to Run

### 1. Install Requirements

```bash
pip install cryptography flask flask-cors
```

Optional — enables YARA rule engine:

```bash
pip install yara-python
```

---

### 2. CLI Scan Mode

```bash
python scanner_v3.py
```

Scans `test_lab/` by default. Output written to:

```txt
reports/scan_report.json
```

Scan a custom path:

```bash
python scanner_v3.py /path/to/target
```

Full CLI options:

```bash
python scanner_v3.py --help

  target                  Path to scan (default: test_lab/)
  --report PATH           Output report path
  --rules-dir PATH        YARA rules directory
  --no-quarantine         Disable auto-quarantine of RED files
  --no-content-scan       Skip text content scanning
  --entropy-threshold N   Float threshold (default: 7.2)
  --serve                 Start web dashboard server
  --host HOST             Server host (default: 127.0.0.1)
  --port PORT             Server port (default: 5000)
  --debug                 Flask debug mode
```

---

### 3. Web Dashboard Mode

```bash
python scanner_v3.py --serve
```

Open in browser:

```
http://127.0.0.1:5000
```

---

### 4. REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Dashboard UI |
| `GET` | `/api/status` | Scanner health + YARA info |
| `GET` | `/api/report` | Latest scan report (JSON) |
| `GET` | `/api/rules` | Loaded YARA rules list |
| `POST` | `/api/scan` | Trigger scan `{ "path": "...", "dry_run": false }` |
| `GET` | `/api/stream` | SSE live scan feed |

---

### 5. Trigger a Scan via API

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
     -H "Content-Type: application/json" \
     -d '{"path": "test_lab"}'
```

Subscribe to live events:

```bash
curl http://127.0.0.1:5000/api/stream
```

---

## 🔄 Quarantine & Restore

### Auto-Quarantine

Triggered when `stoplight == RED`. Files are:
1. Encrypted with Fernet into `/quarantine/filename.vxlocked`
2. Optionally overwritten with 3 passes of random bytes
3. Logged to `logs/vaxinx.log`

### Restore Vaulted Files

```bash
python restore_quarantine.py
```

---

## 🧠 VAXINX Reverse Learning Method

```txt
BUILD      → create the system
TEST       → observe real behavior
BREAK      → find weaknesses
UNDERSTAND → map findings to theory
IMPROVE    → refine the logic
DEPLOY     → publish and verify
```

> **think_like_attacker → act_like_defender**

---

## 🧪 Threat Logic Reference

```txt
IDS  = detect anomalies
IPS  = block threats in-line
SIEM = ingest + correlate logs
DLP  = prevent data exfiltration

risk     = probability × impact
security = prevent → detect → respond → recover
```

---

## 🎓 Verified Credentials

All credentials verified on [Credly](https://www.credly.com/users/regis-lara) and reflected in the dashboard.

| Type | Credential | Issued |
|---|---|---|
| 🏅 Badge | Introduction to Cybersecurity | May 01, 2026 |
| 📜 Certificate | Introduction to Cybersecurity | May 01, 2026 |
| ✅ Achievement | Resource Specialist | May 01, 2026 |
| ✅ Achievement | Network Defense | May 01, 2026 |
| ✅ Achievement | System Safeguards | Apr 29, 2026 |
| ✅ Achievement | Threat Analysis | Apr 26, 2026 |
| ✅ Achievement | Cybersecurity Administration | Apr 26, 2026 |

Issuer: **Cisco Networking Academy**

---

## 📡 Roadmap

- [ ] 🔁 Live folder monitor (auto-scan on file drop)
- [ ] 🌐 Remote scan API integration
- [ ] 🧠 AI anomaly detection layer
- [ ] 📊 Full SIEM dashboard with log correlation
- [ ] 🛰️ NetGuard — network traffic monitor module
- [ ] 🔗 Credly API integration (auto-sync badges to dashboard)

---

## ⚠️ Security Notes

- 🚫 **Never commit `secret.key` or `.vault_keys/`**
- Add to `.gitignore`:

```txt
secret.key
.vault_keys/
quarantine/
logs/
```

- This is a **defensive learning tool only**
- It **does NOT execute scanned files** under any condition

---

## 🧾 License — VAXINX Protocol™

```
Creator : VAXINX (Regis Lara)
Purpose : Educational / Defensive Cybersecurity

✔  Free to use for learning
❌  Not for offensive or malicious use
✔  Attribution required

"One Seed. 12 Phrase. Immunity."
```

---

🛡️ **VAXINX Protocol™** — *You don't just scan files. You understand threats before they happen.*
