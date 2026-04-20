# CyberScan Pro v2

## Setup

```bash
pip install -r requirements.txt
python app.py
```

## Features
- User accounts (register/login/dashboard)
- Deep scan: SSL/TLS + expiry, 6 security headers, 15 port scan, 10 exposed file checks, DNS, tech fingerprinting
- CVSS-style weighted scoring
- Severity tiers: CRITICAL / HIGH / MEDIUM / LOW
- SSRF protection (blocks private IP ranges)
- Rate limiting (10 scans/min)
- CSRF protection
- PDF / JSON / Excel downloads (200+ word report)
- Scan history with trend charts
- Same dark cyberpunk UI as v1

## Routes
- `/` — Home + scanner
- `/scan` — POST scan endpoint
- `/login` `/register` `/logout` — Auth
- `/dashboard` — User scan history
- `/scan/<id>` — View saved scan
- `/scan/delete/<id>` — Delete scan
- `/download/pdf|json|excel/<filename>` — Downloads
![Alt text](image-url-or-path)
