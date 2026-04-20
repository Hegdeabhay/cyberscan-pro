from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import requests, socket, ssl, json, os, re, ipaddress
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
import pandas as pd

# ─────────────────────────────────────────────
#  APP SETUP
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyberscan-dev-secret-2025')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyberscan.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the scanner.'

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

os.makedirs('reports', exist_ok=True)

# ─────────────────────────────────────────────
#  MODELS
# ─────────────────────────────────────────────
class User(UserMixin, db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    username    = db.Column(db.String(80), unique=True, nullable=False)
    email       = db.Column(db.String(120), unique=True, nullable=False)
    password    = db.Column(db.String(256), nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    scans       = db.relationship('ScanResult', backref='user', lazy=True)

class ScanResult(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    target          = db.Column(db.String(256), nullable=False)
    score           = db.Column(db.Integer, default=0)
    risk_level      = db.Column(db.String(20), default='Unknown')
    ssl_valid       = db.Column(db.Boolean, default=False)
    issues_count    = db.Column(db.Integer, default=0)
    risks_count     = db.Column(db.Integer, default=0)
    full_data       = db.Column(db.Text, nullable=False)   # JSON blob
    filename        = db.Column(db.String(256))
    scanned_at      = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

# ─────────────────────────────────────────────
#  SECURITY HELPERS — SSRF PROTECTION
# ─────────────────────────────────────────────
BLOCKED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
]

def is_safe_target(domain):
    """Block private/internal IPs to prevent SSRF."""
    try:
        ip = socket.gethostbyname(domain)
        addr = ipaddress.ip_address(ip)
        for net in BLOCKED_RANGES:
            if addr in net:
                return False
        return True
    except Exception:
        return False

def sanitize_domain(raw):
    raw = raw.strip().lower()
    raw = re.sub(r'^https?://', '', raw)
    raw = raw.split('/')[0]
    if not re.match(r'^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$', raw):
        return None
    return raw

# ─────────────────────────────────────────────
#  SCAN CHECKS
# ─────────────────────────────────────────────
def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_str = cert.get('notAfter', '')
                exp_dt  = datetime.strptime(exp_str, '%b %d %H:%M:%S %Y %Z') if exp_str else None
                days_left = (exp_dt - datetime.utcnow()).days if exp_dt else None
                return {
                    'valid': True,
                    'expires': exp_str,
                    'days_left': days_left,
                    'expiring_soon': days_left is not None and days_left < 30
                }
    except ssl.SSLCertVerificationError:
        return {'valid': False, 'expires': None, 'days_left': None, 'expiring_soon': False, 'error': 'Certificate verification failed'}
    except Exception as e:
        return {'valid': False, 'expires': None, 'days_left': None, 'expiring_soon': False, 'error': str(e)}

def check_headers(url):
    REQUIRED = {
        'X-Frame-Options':          ('DENY or SAMEORIGIN', 'Clickjacking'),
        'Content-Security-Policy':  ('Whitelist trusted sources', 'XSS'),
        'X-Content-Type-Options':   ('nosniff', 'MIME Sniffing'),
        'Strict-Transport-Security':('max-age=31536000', 'SSL Stripping'),
        'Referrer-Policy':          ('no-referrer or strict-origin', 'Data Leakage'),
        'Permissions-Policy':       ('Restrict browser features', 'Feature Abuse'),
    }
    try:
        r = requests.get(url, timeout=8, allow_redirects=True,
                         headers={'User-Agent': 'CyberScanPro/2.0 Security Scanner'})
        hdrs    = r.headers
        issues  = []
        present = []
        for h, (fix, risk) in REQUIRED.items():
            if h not in hdrs:
                issues.append({'header': h, 'fix': fix, 'risk': risk})
            else:
                present.append({'header': h, 'value': hdrs[h][:80]})

        # Cookie check
        cookie_issues = []
        for c in r.cookies:
            flags = []
            if not c.secure:    flags.append('Missing Secure flag')
            if not c.has_nonstandard_attr('HttpOnly'): flags.append('Missing HttpOnly flag')
            if flags:
                cookie_issues.append({'name': c.name, 'issues': flags})

        # HTTP methods
        dangerous_methods = []
        try:
            opts = requests.options(url, timeout=5)
            allow = opts.headers.get('Allow', '')
            for m in ['PUT','DELETE','TRACE','CONNECT']:
                if m in allow:
                    dangerous_methods.append(m)
        except Exception:
            pass

        # Redirect chain
        redirects = [{'url': r2.url, 'status': r2.status_code}
                     for r2 in r.history] if r.history else []

        # Server / tech leakage
        leaks = {}
        for lh in ['Server', 'X-Powered-By', 'X-AspNet-Version']:
            if lh in hdrs:
                leaks[lh] = hdrs[lh]

        return {
            'issues': issues,
            'present': present,
            'cookie_issues': cookie_issues,
            'dangerous_methods': dangerous_methods,
            'redirects': redirects,
            'leaks': leaks,
            'status_code': r.status_code
        }
    except Exception as e:
        return {
            'issues': [], 'present': [], 'cookie_issues': [],
            'dangerous_methods': [], 'redirects': [], 'leaks': {},
            'status_code': None, 'error': str(e)
        }

def check_dns(domain):
    records = {}
    try:
        import subprocess
        for rtype in ['A', 'MX', 'TXT', 'NS']:
            try:
                result = subprocess.run(
                    ['nslookup', f'-type={rtype}', domain],
                    capture_output=True, text=True, timeout=5
                )
                records[rtype] = result.stdout[:400]
            except Exception:
                records[rtype] = 'Unavailable'
    except Exception:
        pass
    return records

def check_ports(domain):
    common_ports = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }
    open_ports = []
    dangerous  = [21, 23, 3306, 3389, 5432, 6379, 27017]
    for port, name in common_ports.items():
        try:
            with socket.create_connection((domain, port), timeout=1):
                open_ports.append({
                    'port': port, 'service': name,
                    'dangerous': port in dangerous
                })
        except Exception:
            pass
    return open_ports

def check_exposed_files(url):
    targets = [
        '/robots.txt', '/sitemap.xml', '/.env', '/config.php',
        '/wp-config.php', '/.git/HEAD', '/admin', '/phpinfo.php',
        '/backup.zip', '/.htaccess'
    ]
    found = []
    for path in targets:
        try:
            r = requests.get(url.rstrip('/') + path, timeout=4, allow_redirects=False)
            if r.status_code in [200, 301, 302]:
                found.append({
                    'path': path,
                    'status': r.status_code,
                    'dangerous': path in ['/.env', '/.git/HEAD', '/phpinfo.php', '/wp-config.php']
                })
        except Exception:
            pass
    return found

# ─────────────────────────────────────────────
#  CVSS-STYLE WEIGHTED SCORING
# ─────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    'CRITICAL': 25,
    'HIGH':     15,
    'MEDIUM':   8,
    'LOW':      3,
    'INFO':     1
}

HEADER_SEVERITY = {
    'Strict-Transport-Security': 'HIGH',
    'Content-Security-Policy':   'HIGH',
    'X-Frame-Options':           'MEDIUM',
    'X-Content-Type-Options':    'MEDIUM',
    'Referrer-Policy':           'LOW',
    'Permissions-Policy':        'LOW',
}

def calculate_score(ssl_data, header_data, ports, exposed):
    deductions = []
    score = 100

    if not ssl_data['valid']:
        deductions.append({'issue': 'No valid SSL certificate', 'severity': 'CRITICAL', 'points': 25})
        score -= 25
    elif ssl_data.get('expiring_soon'):
        deductions.append({'issue': 'SSL certificate expiring soon', 'severity': 'HIGH', 'points': 10})
        score -= 10

    for issue in header_data['issues']:
        sev = HEADER_SEVERITY.get(issue['header'], 'LOW')
        pts = SEVERITY_WEIGHTS[sev]
        deductions.append({'issue': f"Missing {issue['header']}", 'severity': sev, 'points': pts})
        score -= pts

    for p in ports:
        if p['dangerous']:
            deductions.append({'issue': f"Exposed dangerous port {p['port']} ({p['service']})", 'severity': 'HIGH', 'points': 10})
            score -= 10

    for f in exposed:
        if f['dangerous']:
            deductions.append({'issue': f"Exposed sensitive file {f['path']}", 'severity': 'CRITICAL', 'points': 15})
            score -= 15

    if header_data.get('leaks'):
        deductions.append({'issue': 'Server technology headers leaking version info', 'severity': 'MEDIUM', 'points': 5})
        score -= 5 * len(header_data['leaks'])

    for dm in header_data.get('dangerous_methods', []):
        deductions.append({'issue': f'Dangerous HTTP method enabled: {dm}', 'severity': 'HIGH', 'points': 10})
        score -= 10

    score = max(score, 0)
    risk_level = 'LOW' if score >= 80 else 'MEDIUM' if score >= 50 else 'HIGH' if score >= 25 else 'CRITICAL'
    return score, risk_level, deductions

# ─────────────────────────────────────────────
#  RECOMMENDATIONS
# ─────────────────────────────────────────────
def generate_recommendations(results):
    recs  = []
    risks = []

    if not results['ssl']['valid']:
        recs.append({'title': 'Enable SSL/TLS', 'detail': 'Obtain a free certificate from Let\'s Encrypt and configure HTTPS on your server.', 'severity': 'CRITICAL'})
        risks.append({'title': 'Man-in-the-Middle Attack', 'detail': 'All traffic is transmitted in plaintext and can be intercepted.', 'severity': 'CRITICAL'})
    elif results['ssl'].get('expiring_soon'):
        recs.append({'title': 'Renew SSL Certificate', 'detail': f"Certificate expires in {results['ssl']['days_left']} days. Renew immediately.", 'severity': 'HIGH'})

    for issue in results['headers']['issues']:
        h = issue['header']
        if h == 'X-Frame-Options':
            recs.append({'title': 'Add X-Frame-Options', 'detail': 'Set to DENY or SAMEORIGIN in your server config.', 'severity': 'MEDIUM'})
            risks.append({'title': 'Clickjacking Attack', 'detail': 'Attackers can embed your site in an iframe to steal clicks.', 'severity': 'MEDIUM'})
        elif h == 'Content-Security-Policy':
            recs.append({'title': 'Add Content-Security-Policy', 'detail': 'Define a CSP to whitelist trusted content sources.', 'severity': 'HIGH'})
            risks.append({'title': 'Cross-Site Scripting (XSS)', 'detail': 'Malicious scripts can be injected and executed in user browsers.', 'severity': 'HIGH'})
        elif h == 'X-Content-Type-Options':
            recs.append({'title': 'Add X-Content-Type-Options: nosniff', 'detail': 'Prevents MIME-type sniffing attacks.', 'severity': 'MEDIUM'})
            risks.append({'title': 'MIME Sniffing Attack', 'detail': 'Browser may execute files with wrong content type.', 'severity': 'MEDIUM'})
        elif h == 'Strict-Transport-Security':
            recs.append({'title': 'Add HSTS Header', 'detail': 'Add Strict-Transport-Security with max-age=31536000.', 'severity': 'HIGH'})
            risks.append({'title': 'SSL Stripping Attack', 'detail': 'Attackers can downgrade HTTPS connections to HTTP.', 'severity': 'HIGH'})
        elif h == 'Referrer-Policy':
            recs.append({'title': 'Add Referrer-Policy', 'detail': 'Set to no-referrer or strict-origin-when-cross-origin.', 'severity': 'LOW'})
            risks.append({'title': 'Referrer Data Leakage', 'detail': 'Sensitive URLs may be leaked via the Referer header.', 'severity': 'LOW'})
        elif h == 'Permissions-Policy':
            recs.append({'title': 'Add Permissions-Policy', 'detail': 'Restrict access to browser features like camera, microphone.', 'severity': 'LOW'})
            risks.append({'title': 'Unauthorized Feature Access', 'detail': 'Embedded scripts may access sensitive browser APIs.', 'severity': 'LOW'})

    for p in results.get('ports', []):
        if p['dangerous']:
            recs.append({'title': f"Close Port {p['port']} ({p['service']})", 'detail': f"Port {p['port']} should not be publicly accessible.", 'severity': 'HIGH'})
            risks.append({'title': f"Exposed {p['service']} Service", 'detail': f"Port {p['port']} is open and may be targeted by attackers.", 'severity': 'HIGH'})

    if results['headers'].get('leaks'):
        recs.append({'title': 'Remove Server Version Headers', 'detail': 'Configure your server to hide version info from response headers.', 'severity': 'MEDIUM'})
        risks.append({'title': 'Technology Fingerprinting', 'detail': 'Attackers can use version info to find known exploits.', 'severity': 'MEDIUM'})

    for f in results.get('exposed_files', []):
        if f['dangerous']:
            recs.append({'title': f"Restrict access to {f['path']}", 'detail': f"This sensitive file is publicly accessible. Block it immediately.", 'severity': 'CRITICAL'})
            risks.append({'title': f"Exposed Sensitive File: {f['path']}", 'detail': 'Credentials, configs, or source code may be exposed.', 'severity': 'CRITICAL'})

    return recs, risks

# ─────────────────────────────────────────────
#  DETAILED ANALYSIS TEXT (200+ WORDS)
# ─────────────────────────────────────────────
def generate_analysis_text(data):
    t      = data['target']
    score  = data['score']
    rl     = data['risk_level']
    ssl_ok = data['ssl']['valid']
    issues = data['headers']['issues']
    risks  = data['risks']
    recs   = data['recommendations']
    ports  = data.get('ports', [])
    exp    = data.get('exposed_files', [])

    return (
        f"EXECUTIVE SUMMARY\n\n"
        f"This automated security vulnerability assessment was conducted against '{t}' on "
        f"{data['timestamp'][:19]} UTC. The system achieved a weighted security score of {score}/100, "
        f"classifying the overall risk level as {rl}. The assessment evaluated SSL/TLS integrity, "
        f"HTTP security headers, open network ports, exposed sensitive files, cookie security flags, "
        f"HTTP method exposure, and server technology leakage — covering seven distinct attack surface dimensions.\n\n"

        f"SSL/TLS CERTIFICATE ANALYSIS\n\n"
        f"The SSL/TLS certificate status is: {'VALID' if ssl_ok else 'INVALID/ABSENT'}. "
        + (f"Certificate expires in {data['ssl'].get('days_left', 'N/A')} days. "
           f"{'WARNING: Certificate is expiring soon and must be renewed immediately.' if data['ssl'].get('expiring_soon') else 'Certificate validity is within acceptable range.'}"
           if ssl_ok else
           "An absent or invalid certificate means all data is transmitted in plaintext. "
           "This exposes users to Man-in-the-Middle attacks, credential interception, and session hijacking. "
           "Immediate installation of a valid TLS certificate via Let's Encrypt or a commercial CA is required."
           ) + "\n\n"

        f"SECURITY HEADER ASSESSMENT\n\n"
        f"{len(issues)} out of 6 required security header(s) are missing. "
        f"Security headers are critical HTTP response directives that instruct browsers how to handle content, "
        f"preventing client-side attacks such as XSS, clickjacking, and MIME sniffing. "
        + (f"Missing headers: {', '.join(i['header'] for i in issues)}. Each absent header represents "
           f"a concrete exploitable weakness in the browser security model."
           if issues else "All six critical security headers are present, indicating excellent header hygiene."
           ) + "\n\n"

        f"NETWORK PORT EXPOSURE\n\n"
        f"{len(ports)} port(s) found open during the scan. "
        + (f"Dangerous ports detected: {', '.join(str(p['port'])+'/'+p['service'] for p in ports if p['dangerous'])}. "
           f"Publicly exposed database and remote-access ports are a primary attack vector for "
           f"credential brute-forcing, ransomware deployment, and lateral movement."
           if any(p['dangerous'] for p in ports)
           else "No critically dangerous ports detected on common service ranges."
           ) + "\n\n"

        f"SENSITIVE FILE EXPOSURE\n\n"
        + (f"{len([f for f in exp if f['dangerous']])} sensitive file(s) were publicly accessible: "
           f"{', '.join(f['path'] for f in exp if f['dangerous'])}. "
           f"Exposed configuration files and environment files can reveal database credentials, "
           f"API keys, and internal infrastructure details to unauthenticated attackers."
           if any(f['dangerous'] for f in exp)
           else "No sensitive or dangerous files were found publicly accessible."
           ) + "\n\n"

        f"RISK VECTORS\n\n"
        + (f"The following {len(risks)} risk vector(s) were identified: "
           + "; ".join(r['title'] for r in risks) + ". "
           f"These vulnerabilities can be leveraged individually or chained together to achieve "
           f"full account compromise, data exfiltration, or service disruption."
           if risks else "No critical risk vectors identified in this assessment."
           ) + "\n\n"

        f"REMEDIATION ROADMAP\n\n"
        + (f"{len(recs)} remediation action(s) are recommended: "
           + " | ".join(f"({i+1}) {r['title']}" for i, r in enumerate(recs)) + ". "
           f"Priority should be given to CRITICAL and HIGH severity items first, "
           f"particularly SSL certificate installation and HSTS enforcement."
           if recs else "No immediate remediation required. Maintain current security posture with periodic scans."
           ) + "\n\n"

        f"CONCLUSION\n\n"
        f"The domain '{t}' received a final security score of {score}/100 ({rl} RISK). "
        f"{'The system demonstrates strong security practices across all tested dimensions.' if score >= 80 else 'Immediate remediation is required to address critical and high severity findings.' if score < 50 else 'Moderate improvements will significantly strengthen the security posture.'} "
        f"Regular automated scans, patch management, and adherence to OWASP Top 10 guidelines "
        f"are recommended as part of a continuous security monitoring program. "
        f"This report should be reviewed by a qualified security professional and is not a substitute "
        f"for a comprehensive manual penetration test."
    )

# ─────────────────────────────────────────────
#  ROUTES — PUBLIC
# ─────────────────────────────────────────────
@app.route('/')
def index():
    recent = []
    if current_user.is_authenticated:
        recent = ScanResult.query.filter_by(user_id=current_user.id)\
                    .order_by(ScanResult.scanned_at.desc()).limit(5).all()
    return render_template('index.html', recent=recent)

@app.route('/scan', methods=['POST'])
@limiter.limit("10 per minute")
def scan():
    raw = request.form.get('url', '').strip()
    domain = sanitize_domain(raw)
    if not domain:
        flash('Invalid domain format. Please enter a valid hostname.', 'error')
        return redirect(url_for('index'))

    if not is_safe_target(domain):
        flash('Target blocked: Internal/private IP ranges are not permitted.', 'error')
        return redirect(url_for('index'))

    url = 'https://' + domain

    ssl_data     = check_ssl(domain)
    header_data  = check_headers(url)
    ports        = check_ports(domain)
    exposed      = check_exposed_files(url)
    dns_records  = check_dns(domain)

    score, risk_level, deductions = calculate_score(ssl_data, header_data, ports, exposed)

    results = {
        'target':       domain,
        'url':          url,
        'timestamp':    str(datetime.utcnow()),
        'ssl':          ssl_data,
        'headers':      header_data,
        'ports':        ports,
        'exposed_files': exposed,
        'dns':          dns_records,
        'score':        score,
        'risk_level':   risk_level,
        'deductions':   deductions,
    }
    recs, risks = generate_recommendations(results)
    results['recommendations'] = recs
    results['risks']           = risks
    results['analysis_text']   = generate_analysis_text(results)

    safe     = re.sub(r'[^a-zA-Z0-9]', '_', domain)
    filename = f"report_{safe}_{int(datetime.utcnow().timestamp())}.json"
    fpath    = os.path.join('reports', filename)
    with open(fpath, 'w') as f:
        json.dump(results, f, indent=2)

    # Save to DB
    scan_row = ScanResult(
        user_id     = current_user.id if current_user.is_authenticated else None,
        target      = domain,
        score       = score,
        risk_level  = risk_level,
        ssl_valid   = ssl_data['valid'],
        issues_count= len(header_data['issues']),
        risks_count = len(risks),
        full_data   = json.dumps(results),
        filename    = filename
    )
    db.session.add(scan_row)
    db.session.commit()

    return render_template('result.html', data=results, filename=filename, scan_id=scan_row.id)

# ─────────────────────────────────────────────
#  ROUTES — AUTH
# ─────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')
        u = User(username=username, email=email,
                 password=generate_password_hash(password))
        db.session.add(u)
        db.session.commit()
        login_user(u)
        flash('Account created! Welcome to CyberScan Pro.', 'success')
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password   = request.form.get('password', '')
        u = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()
        if u and check_password_hash(u.password, password):
            login_user(u, remember=request.form.get('remember') == 'on')
            flash(f'Welcome back, {u.username}!', 'success')
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

# ─────────────────────────────────────────────
#  ROUTES — DASHBOARD
# ─────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    scans = ScanResult.query.filter_by(user_id=current_user.id)\
                .order_by(ScanResult.scanned_at.desc()).all()
    avg_score = round(sum(s.score for s in scans) / len(scans), 1) if scans else 0
    return render_template('dashboard.html', scans=scans, avg_score=avg_score)

@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id and (not current_user.is_authenticated or scan.user_id != current_user.id):
        flash('Access denied.', 'error')
        return redirect(url_for('index'))
    data = json.loads(scan.full_data)
    return render_template('result.html', data=data, filename=scan.filename, scan_id=scan.id)

@app.route('/scan/delete/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return redirect(url_for('dashboard'))

# ─────────────────────────────────────────────
#  ROUTES — DOWNLOADS
# ─────────────────────────────────────────────
@app.route('/download/json/<filename>')
def download_json(filename):
    return send_file(os.path.join('reports', filename), as_attachment=True)

@app.route('/download/excel/<filename>')
def download_excel(filename):
    path = os.path.join('reports', filename)
    with open(path) as f:
        data = json.load(f)
    flat = {
        'Target': data['target'], 'Score': data['score'],
        'Risk Level': data['risk_level'], 'SSL Valid': data['ssl']['valid'],
        'Scanned At': data['timestamp'],
        'Issues': len(data['headers']['issues']),
        'Risks': len(data['risks']),
        'Open Ports': len(data.get('ports', [])),
        'Exposed Files': len(data.get('exposed_files', [])),
    }
    df = pd.DataFrame([flat])
    ep = path.replace('.json', '.xlsx')
    df.to_excel(ep, index=False)
    return send_file(ep, as_attachment=True)

@app.route('/download/pdf/<filename>')
def download_pdf(filename):
    path = os.path.join('reports', filename)
    with open(path) as f:
        data = json.load(f)

    pdf_path = path.replace('.json', '.pdf')
    doc = SimpleDocTemplate(pdf_path,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()

    T  = lambda txt, s: Paragraph(txt, s)
    SP = lambda h=10: Spacer(1, h)
    HR = lambda: HRFlowable(width='100%', thickness=1, color=colors.HexColor('#ccddee'))

    title_s   = ParagraphStyle('t',  fontName='Helvetica-Bold', fontSize=22,
                                textColor=colors.HexColor('#003366'), alignment=TA_CENTER, spaceAfter=4)
    sub_s     = ParagraphStyle('sb', fontName='Helvetica', fontSize=11,
                                textColor=colors.HexColor('#666'), alignment=TA_CENTER, spaceAfter=18)
    sec_s     = ParagraphStyle('sc', fontName='Helvetica-Bold', fontSize=13,
                                textColor=colors.HexColor('#003366'), spaceBefore=14, spaceAfter=6)
    body_s    = ParagraphStyle('bd', fontName='Helvetica', fontSize=10, leading=16,
                                textColor=colors.HexColor('#222'), alignment=TA_JUSTIFY, spaceAfter=8)
    bullet_s  = ParagraphStyle('bl', fontName='Helvetica', fontSize=10, leading=14,
                                textColor=colors.HexColor('#333'), leftIndent=14, spaceAfter=4)
    ok_s      = ParagraphStyle('ok', fontName='Helvetica', fontSize=10, leading=14,
                                textColor=colors.HexColor('#006633'), leftIndent=14, spaceAfter=4)
    warn_s    = ParagraphStyle('wn', fontName='Helvetica', fontSize=10, leading=14,
                                textColor=colors.HexColor('#cc3300'), leftIndent=14, spaceAfter=4)
    crit_s    = ParagraphStyle('cr', fontName='Helvetica-Bold', fontSize=10, leading=14,
                                textColor=colors.HexColor('#990000'), leftIndent=14, spaceAfter=4)
    disc_s    = ParagraphStyle('ds', fontName='Helvetica-Oblique', fontSize=8,
                                textColor=colors.HexColor('#888'), alignment=TA_CENTER)

    score      = data['score']
    risk_label = data['risk_level']
    sc         = (colors.HexColor('#006633') if score >= 80
                  else colors.HexColor('#cc7700') if score >= 50
                  else colors.HexColor('#cc0000'))

    content = []
    content.append(T('CyberScan Pro', title_s))
    content.append(T('Automated Security Vulnerability Assessment Report', sub_s))
    content.append(HR())
    content.append(SP(14))

    meta = [
        ['Target Domain',  data['target']],
        ['Scan Timestamp', data['timestamp'][:19] + ' UTC'],
        ['Security Score', f"{score}/100"],
        ['Risk Level',     risk_label],
        ['SSL Status',     'VALID' if data['ssl']['valid'] else 'INVALID'],
        ['Headers Issues', str(len(data['headers']['issues']))],
        ['Open Ports',     str(len(data.get('ports', [])))],
        ['Exposed Files',  str(len(data.get('exposed_files', [])))],
    ]
    mt = Table(meta, colWidths=[2.2*inch, 4.6*inch])
    mt.setStyle(TableStyle([
        ('BACKGROUND',  (0,0),(0,-1), colors.HexColor('#e8f0f8')),
        ('FONTNAME',    (0,0),(0,-1), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0),(-1,-1), 10),
        ('BOX',         (0,0),(-1,-1), 1, colors.HexColor('#ccddee')),
        ('INNERGRID',   (0,0),(-1,-1), 0.5, colors.HexColor('#e0eef5')),
        ('ROWBACKGROUNDS',(0,0),(-1,-1),[colors.HexColor('#f0f5fa'), colors.white]),
        ('PADDING',     (0,0),(-1,-1), 8),
        ('TEXTCOLOR',   (1,2),(1,2), sc),
        ('FONTNAME',    (1,2),(1,2), 'Helvetica-Bold'),
        ('FONTSIZE',    (1,2),(1,2), 14),
    ]))
    content.append(mt)
    content.append(SP(18))

    # Analysis sections
    for section in data.get('analysis_text', '').split('\n\n'):
        if not section.strip(): continue
        lines = section.strip().split('\n')
        hdr   = lines[0].strip()
        if hdr.isupper() and len(lines) > 1:
            content.append(T(hdr, sec_s))
            body = ' '.join(l.strip() for l in lines[1:] if l.strip())
            content.append(T(body, body_s))
        else:
            content.append(T(section.strip(), body_s))

    content.append(SP(8)); content.append(HR()); content.append(SP(12))

    # Detailed findings
    content.append(T('DETAILED FINDINGS', sec_s))

    # SSL
    content.append(T('SSL/TLS Certificate', ParagraphStyle('sh', fontName='Helvetica-Bold',
                    fontSize=11, textColor=colors.HexColor('#333'), spaceAfter=4, spaceBefore=10)))
    if data['ssl']['valid']:
        content.append(T(f"✓  VALID — Expires: {data['ssl'].get('expires','N/A')} ({data['ssl'].get('days_left','?')} days remaining)", ok_s))
    else:
        content.append(T(f"✗  INVALID — {data['ssl'].get('error','Certificate check failed')}", warn_s))
    content.append(SP(8))

    # Security Headers
    content.append(T('Security Headers', ParagraphStyle('sh2', fontName='Helvetica-Bold',
                    fontSize=11, textColor=colors.HexColor('#333'), spaceAfter=4, spaceBefore=6)))
    for issue in data['headers']['issues']:
        sev   = HEADER_SEVERITY.get(issue['header'], 'LOW')
        style = crit_s if sev in ('CRITICAL','HIGH') else warn_s
        content.append(T(f"✗  [{sev}] Missing {issue['header']} — Risk: {issue['risk']}", style))
    for p in data['headers'].get('present', []):
        content.append(T(f"✓  {p['header']}: {p['value']}", ok_s))
    content.append(SP(8))

    # Ports
    if data.get('ports'):
        content.append(T('Open Ports', ParagraphStyle('ph', fontName='Helvetica-Bold',
                        fontSize=11, textColor=colors.HexColor('#333'), spaceAfter=4, spaceBefore=6)))
        for p in data['ports']:
            s = crit_s if p['dangerous'] else bullet_s
            marker = '⚠' if p['dangerous'] else '•'
            content.append(T(f"{marker}  Port {p['port']} — {p['service']} {'[DANGEROUS]' if p['dangerous'] else ''}", s))
        content.append(SP(8))

    # Exposed Files
    if data.get('exposed_files'):
        content.append(T('Exposed Files', ParagraphStyle('ef', fontName='Helvetica-Bold',
                        fontSize=11, textColor=colors.HexColor('#333'), spaceAfter=4, spaceBefore=6)))
        for f in data['exposed_files']:
            s = crit_s if f['dangerous'] else warn_s
            content.append(T(f"⚠  {f['path']} (HTTP {f['status']}) {'[CRITICAL]' if f['dangerous'] else ''}", s))
        content.append(SP(8))

    # Recommendations
    content.append(HR()); content.append(SP(10))
    content.append(T('REMEDIATION RECOMMENDATIONS', sec_s))
    for rec in data['recommendations']:
        sev   = rec.get('severity', 'LOW')
        style = crit_s if sev == 'CRITICAL' else warn_s if sev == 'HIGH' else bullet_s
        content.append(T(f"[{sev}] {rec['title']}: {rec['detail']}", style))

    content.append(SP(16)); content.append(HR()); content.append(SP(8))
    content.append(T(
        'DISCLAIMER: CyberScan Pro is for authorized use only. Results are indicative and do not '
        'constitute a comprehensive security audit. Consult a qualified security professional for critical systems.',
        disc_s
    ))

    doc.build(content)
    return send_file(pdf_path, as_attachment=True)

# ─────────────────────────────────────────────
#  INIT DB + RUN
# ─────────────────────────────────────────────
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
