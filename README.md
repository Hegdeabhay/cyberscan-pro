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
<img width="1600" height="756" alt="First Image" src="https://github.com/user-attachments/assets/3d430704-2979-4e99-a37a-f5486bc8e49d" />
<img width="1600" height="484" alt="image" src="https://github.com/user-attachments/assets/cc89fb40-3f86-43e6-980c-2f9608bbdf16" />
<img width="1600" height="737" alt="image" src="https://github.com/user-attachments/assets/69b5a795-5ea4-44a6-8205-a2b0a6aa0cd2" />
<img width="1600" height="677" alt="image" src="https://github.com/user-attachments/assets/247a09d7-95c5-4c00-8483-c1ede777180e" />
<img width="1600" height="581" alt="image" src="https://github.com/user-attachments/assets/0b4b83f0-c15a-4998-8fe9-146048651b36" />
<img width="1600" height="684" alt="image" src="https://github.com/user-attachments/assets/0e8644bc-2860-466e-9df7-12a75cdcf46c" />




