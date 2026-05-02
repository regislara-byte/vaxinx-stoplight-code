# 🛡️ VAXINX – Stoplight Code of the Web

> VAXINX evaluates incoming files using a stoplight-style cyber defense model.

```text
Incoming File → VAXINX Gate → Threat Intelligence → Stoplight Decision

🟢 GREEN  = Allow
🟡 YELLOW = Inspect
🔴 RED    = Quarantine
```

## v3 Upgrade

This version adds deeper defensive detection:

- PE / `.exe` header check (`MZ` magic bytes)
- Double-extension disguise detection
- Script detection: `.bat`, `.cmd`, `.vbs`, `.js`, `.ps1`
- Macro document detection: `.docm`, `.xlsm`, `.pptm`
- Archive/container detection: `.zip`, `.rar`, `.7z`
- Suspicious keyword scoring
- Malware-type mapping:
  - Virus
  - Trojan
  - Worm
  - Ransomware
  - Spyware
  - Adware
  - Scareware
  - Backdoor
  - Rootkit
- Quarantine / Alcatraz Mode
- JSON report + dashboard

## Run

```bash
python scanner.py
python -m http.server
```

Open:

```text
http://localhost:8000/index.html
```

## Safety

This is an educational defensive scanner. It does not execute files, create malware, bypass security, or remove system protections.
