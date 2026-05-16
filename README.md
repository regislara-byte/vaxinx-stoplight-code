# 🛡️ VAXINX Stoplight Scanner — v3.0-VAULT

> **think_like_attacker → act_like_defender**

A **Python + JSON + HTML hybrid cybersecurity tool** that simulates real-world defensive analysis using a **Stoplight Risk Model (RED / YELLOW / GREEN)**.

Part of the **VAXINX Protocol™** ecosystem — a reverse-learning engineering system where:

```txt
BUILD → TEST → BREAK → UNDERSTAND → IMPROVE → DEPLOY
```

This project combines:

- defensive cybersecurity concepts
- AI-assisted engineering workflows
- visual-first documentation
- modular architecture
- rapid iteration pipelines
- automation-assisted deployment

---

# 🌐 Ecosystem Links

| Platform | Link |
|---|---|
| 🧠 GitHub | https://github.com/regislara-byte |
| 📡 Live Dashboard | https://regislara-byte.github.io/vaxinx-cert-dashboard/ |
| 🎓 Credly | https://www.credly.com/users/regis-lara |

---

# ⚡ What's New in v3.0-VAULT

| Feature | Details |
|---|---|
| 🤖 YARA Rule Engine | Loads all `.yar` / `.yara` rules from `rules/` |
| 🌐 Flask REST API | Live scan API + dashboard serving |
| 📡 SSE Streaming | Real-time file-by-file scan feed |
| 🔐 Quarantine Vault | Fernet encrypted `.vxlocked` files |
| 🎨 Dashboard Alignment | Integrated VAXINX dashboard ecosystem |
| 🧾 Visual Lore Artifacts | AI-readable engineering documentation workflow |
| ⚙️ Automation Pipeline | Batch deployment + push workflow system |

---

# 🚦 Stoplight Risk Model

| Signal | Decision | Action |
|---|---|---|
| 🟢 GREEN | Allow | Safe — no threat indicators detected |
| 🟡 YELLOW | Inspect | Suspicious — manual review required |
| 🔴 RED | Quarantine | High risk — encrypted into `.vxlocked` vault |

---

# 🧬 VAXINX Evolution Phases

## 🟢 PHASE 1 — Scanner Core

Foundation systems:

- stoplight classification
- extension analysis
- JSON reporting
- quarantine architecture
- CLI scanning

---

## 🟡 PHASE 2 — Defensive Analysis Expansion

Detection upgrades:

- entropy analysis
- suspicious keyword logic
- archive inspection
- behavior heuristics
- social engineering pattern checks

---

## 🔴 PHASE 3 — Vault Encryption Layer

Security enhancements:

- Fernet encryption
- `.vxlocked` quarantine vault
- restore workflow
- secure overwrite concepts
- logging infrastructure

---

## 🔵 PHASE 4 — Live Ecosystem Integration

Operational upgrades:

- YARA integration
- Flask REST API
- SSE live stream
- dashboard synchronization
- runtime monitoring

---

## 🟣 PHASE 5 — VLA + Automation Workflow

Engineering acceleration systems:

- Visual Lore Artifacts (VLA)
- AI-readable architecture documentation
- push automation scripts
- deployment pipeline structure
- workflow optimization

---

# 🧠 Core System Modules

```txt
VAXINX_SYSTEM = {
  "file_scanner":    "Python-based threat detection engine",
  "stoplight_logic": "RED / YELLOW / GREEN classification",
  "yara_engine":     "Rule-based pattern matching",
  "flask_api":       "REST API + SSE live stream",
  "vault_engine":    "Encrypted quarantine system",
  "json_reports":    "Structured scan output",
  "html_dashboard":  "Visual cyber intelligence UI",
  "vla_system":      "Visual Lore Artifacts workflow",
  "automation":      "Deployment + push workflow pipeline"
}
```

---

# 🔍 Detection Engine

## File Analysis

- Extension risk classification
- Magic byte scanning
- Entropy analysis
- Suspicious filename detection
- Malware behavior hints
- Social engineering pattern analysis
- Hash-based deduplication

---

## Advanced Detection

- YARA rule integration
- Script content scanning
- Encoded payload detection
- Nested archive inspection
- Pattern correlation

---

## Quarantine Vault

Triggered automatically when:

```txt
stoplight == RED
```

Features:

- Fernet encryption
- `.vxlocked` vault storage
- optional overwrite flow
- restoration pipeline
- runtime logging

---

# 📁 Project Structure

```txt
vaxinx-stoplight-code/
├── scanner_v3.py
├── restore_quarantine.py
├── vaxinx_crypto.py
├── README.md
│
├── automation/
│   ├── push_all.bat
│   ├── push_readme.bat
│   ├── push_dashboard.bat
│   ├── push_vla.bat
│   ├── deploy_dashboard.bat
│   ├── launch_scanner.bat
│   └── install_deps_py312.bat
│
├── dashboard/
│   ├── index.html
│   └── Vaxinx_Doppio.gif
│
├── assets/
│   └── visualloreartifacts/
│       ├── 001-python312-install.png
│       ├── 002-yara-ok-repl.png
│       ├── 003-crypto-dependency-fix.png
│       ├── 004-vscode-interpreter-switch.png
│       └── 005-scanner-runtime-validation.png
│
├── test_lab/
├── quarantine/
├── reports/
├── logs/
├── rules/
└── .vault_keys/
```

---

# 🖼️ Visual Lore Artifacts (VLA)

This repository follows a:

```txt
Visual Lore Artifacts (VLA)
```

workflow philosophy.

The folder:

```txt
assets/visualloreartifacts/
```

contains timestamped screenshots documenting:

- dependency fixes
- Python environment migration
- YARA integration
- cryptography setup
- terminal debugging
- architecture evolution
- dashboard synchronization
- deployment workflows
- VS Code configuration
- runtime validation

---

## 🎯 Purpose of VLA

VLA exists to provide:

- faster human onboarding
- AI-readable engineering context
- visual debugging memory
- architecture evolution tracking
- workflow storytelling
- reproducible environment validation

---

## 🧠 VLA Philosophy

Instead of only reading code:

```txt
README → code → guess architecture
```

VLA enables:

```txt
screenshot → instant context → faster understanding
```

This creates:

- visual-first engineering documentation
- accelerated onboarding
- easier troubleshooting
- long-term project memory

---

# ⚙️ Automation Workflow

This project uses lightweight `.bat` automation systems to accelerate deployment and reduce repetitive terminal workflows.

---

## Automation Structure

```txt
automation/
├── push_all.bat
├── push_readme.bat
├── push_dashboard.bat
├── push_vla.bat
├── deploy_dashboard.bat
├── launch_scanner.bat
└── install_deps_py312.bat
```

---

## ⚡ Purpose

- Faster GitHub pushes
- Cleaner deployment flow
- Reduced command repetition
- Easier dependency restoration
- Faster VLA updates
- Consistent engineering workflow

---

## 🧠 Automation Philosophy

```txt
Automate the friction.
Preserve the thinking.
```

Coding logic, architecture, and security reasoning remain human-directed.

Automation handles:

- repetitive Git operations
- environment restoration
- launch workflows
- deployment shortcuts

---

# ▶️ How to Run

## 1. Recommended Environment

Recommended:

- Python 3.12
- VS Code
- Python Extension
- Windows PowerShell or VS Code Terminal

Python 3.12 is recommended for:

- YARA compatibility
- cybersecurity libraries
- stable dependency support

---

## 2. Install Dependencies

Core packages:

```bash
py -3.12 -m pip install cryptography flask flask-cors
```

Optional YARA support:

```bash
py -3.12 -m pip install yara-python
```

---

## 3. Run Scanner

```bash
py -3.12 scanner_v3.py
```

Default scan target:

```txt
test_lab/
```

Reports generated to:

```txt
reports/scan_report.json
```

---

## 4. Web Dashboard Mode

```bash
py -3.12 scanner_v3.py --serve
```

Open browser:

```txt
http://127.0.0.1:5000
```

---

## 5. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Dashboard UI |
| GET | `/api/status` | Scanner health |
| GET | `/api/report` | Latest scan report |
| GET | `/api/rules` | Loaded YARA rules |
| POST | `/api/scan` | Trigger scan |
| GET | `/api/stream` | Live SSE feed |

---

# 🔄 Quarantine & Restore

## Auto-Quarantine

Triggered automatically on:

```txt
RED classification
```

Flow:

1. File encrypted with Fernet
2. Stored as `.vxlocked`
3. Logged into runtime logs
4. Optional overwrite process

---

## Restore Vaulted Files

```bash
py -3.12 restore_quarantine.py
```

---

# 🧪 Threat Logic Reference

```txt
IDS  = detect anomalies
IPS  = block threats inline
SIEM = correlate logs
DLP  = prevent data exfiltration

risk     = probability × impact
security = prevent → detect → respond → recover
```

---

# 🎓 Verified Credentials

All certifications reflected in the VAXINX dashboard ecosystem.

| Type | Credential |
|---|---|
| 🏅 Badge | Introduction to Cybersecurity |
| 📜 Certificate | Introduction to Cybersecurity |
| ✅ Achievement | Resource Specialist |
| ✅ Achievement | Network Defense |
| ✅ Achievement | System Safeguards |
| ✅ Achievement | Threat Analysis |
| ✅ Achievement | Cybersecurity Administration |

Issuer:

```txt
Cisco Networking Academy
```

---

# 📡 Roadmap

- [ ] Live folder monitoring
- [ ] Remote scan API
- [ ] AI anomaly detection
- [ ] SIEM expansion
- [ ] NetGuard integration
- [ ] Auto dashboard synchronization
- [ ] VLA indexing system
- [ ] GitHub Pages deployment refinement

---

# ⚠️ Security Notes

## Never Commit

```txt
secret.key
.vault_keys/
```

Recommended `.gitignore`:

```txt
secret.key
.vault_keys/
quarantine/
logs/
*.pyc
__pycache__/
```

---

## Recommended Practice

Use `.gitignore` aggressively for:

- runtime artifacts
- encryption keys
- logs
- quarantine data
- local secrets
- temporary payloads
- experimental test files

---

## Important

This project:

- does NOT execute scanned payloads
- is designed for defensive learning
- focuses on detection + workflow simulation
- exists for educational cybersecurity engineering

---

# 🧠 Engineering Philosophy

This repository is intentionally designed as:

- a defensive cybersecurity learning system
- an AI-assisted engineering workflow
- a modular experimentation environment
- a visual-first architecture documentation project
- a deployment workflow ecosystem

The goal is not only to build tools,
but to document:

- debugging
- dependency resolution
- architecture evolution
- workflow refinement
- environment migration
- automation systems
- engineering decision trails

---

# 🧾 License — VAXINX Protocol™

```txt
Creator : VAXINX (Regis Lara)
Purpose : Educational / Defensive Cybersecurity

✔ Free to use for learning
❌ Not for offensive or malicious use
✔ Attribution required

"One Seed. 12 Phrase. Immunity."
```

---

🛡️ **VAXINX Protocol™** — You don't just scan files. You understand threats before they happen.

