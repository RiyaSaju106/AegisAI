from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
import re
import sqlite3
from datetime import datetime, timedelta

load_dotenv()

# Initialize database
def init_db():
    conn = sqlite3.connect('aegisai_stats.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  scan_type TEXT,
                  risk_level TEXT,
                  risk_score INTEGER)''')
    conn.commit()
    conn.close()

def log_scan(scan_type, risk_level, risk_score):
    try:
        conn = sqlite3.connect('aegisai_stats.db')
        c = conn.cursor()
        c.execute('INSERT INTO scans (timestamp, scan_type, risk_level, risk_score) VALUES (?, ?, ?, ?)',
                  (datetime.now().isoformat(), scan_type, risk_level, risk_score))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging scan: {e}")

def get_stats():
    try:
        conn = sqlite3.connect('aegisai_stats.db')
        c = conn.cursor()
        
        # Total scans
        c.execute('SELECT COUNT(*) FROM scans')
        total_scans = c.fetchone()[0]
        
        # Threats (HIGH/MEDIUM risk)
        c.execute('SELECT COUNT(*) FROM scans WHERE risk_level IN ("HIGH", "MEDIUM")')
        threats = c.fetchone()[0]
        
        # Today's scans
        today = datetime.now().date().isoformat()
        c.execute('SELECT COUNT(*) FROM scans WHERE DATE(timestamp) = ?', (today,))
        today_scans = c.fetchone()[0]
        
        # Last 7 days data for chart
        c.execute('''SELECT DATE(timestamp) as date, COUNT(*) as count 
                     FROM scans 
                     WHERE timestamp >= date('now', '-7 days')
                     GROUP BY DATE(timestamp)
                     ORDER BY date''')
        chart_data = [{'date': row[0], 'scans': row[1]} for row in c.fetchall()]
        
        # Scan type breakdown
        c.execute('SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type')
        scan_types = dict(c.fetchall())
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'threats_blocked': threats,
            'today_scans': today_scans,
            'chart_data': chart_data,
            'scan_types': scan_types
        }
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {
            'total_scans': 0, 
            'threats_blocked': 0, 
            'today_scans': 0,
            'chart_data': [],
            'scan_types': {}
        }

# Initialize database on startup
init_db()

app = Flask(__name__)
CORS(app)

# Get API key from .env
GOOGLE_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_KEY')

print(f"🔑 API Key loaded: {GOOGLE_API_KEY[:20]}..." if GOOGLE_API_KEY else "❌ No API key found!")


# ============== URL CHECKER ==============

def check_url_with_google(url):
    """Check URL against Google Safe Browsing"""
    if not GOOGLE_API_KEY:
        return {'error': 'No API key', 'risk_score': 0}
    
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    
    payload = {
        "client": {"clientId": "aegisai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        print(f"Google API Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if 'matches' in data and len(data['matches']) > 0:
                return {
                    'threat_found': True,
                    'threat_type': data['matches'][0]['threatType'],
                    'risk_score': 90
                }
        return {'threat_found': False, 'risk_score': 0}
    except Exception as e:
        print(f"Error calling Google API: {e}")
        return {'error': str(e), 'risk_score': 0}


def analyze_url_structure(url):
    """Analyze URL for suspicious patterns"""
    risk_score = 0
    warnings = []
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        url_lower = url.lower()
        
        # Check for IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            risk_score += 30
            warnings.append("❌ Uses IP address instead of domain")
        
        # Suspicious keywords
        suspicious = ['verify', 'account', 'update', 'secure', 'banking', 
                     'suspended', 'confirm', 'urgent', 'click', 'prize', 'winner']
        for word in suspicious:
            if word in url_lower:
                risk_score += 8
                warnings.append(f"⚠️ Suspicious word: '{word}'")
        
        # @ symbol
        if '@' in url:
            risk_score += 40
            warnings.append("❌ Contains '@' (phishing trick)")
        
        # Too many subdomains
        if domain.count('.') > 3:
            risk_score += 15
            warnings.append(f"⚠️ Many subdomains ({domain.count('.')})")
        
        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
        if any(s in domain for s in shorteners):
            risk_score += 20
            warnings.append("⚠️ URL shortener (hides destination)")
        
        # Long URL
        if len(url) > 100:
            risk_score += 10
            warnings.append("⚠️ Unusually long URL")
        
        return {'risk_score': min(risk_score, 100), 'warnings': warnings}
    except:
        return {'risk_score': 0, 'warnings': []}


# ============== TEXT ANALYZER ==============

def analyze_text_for_scams(text):
    """Analyze text for scam patterns"""
    risk_score = 0
    warnings = []
    text_lower = text.lower()
    
    # Urgent language
    urgent = ['act now', 'urgent', 'immediate', 'expire', 'limited time', 'hurry', 'last chance']
    for phrase in urgent:
        if phrase in text_lower:
            risk_score += 15
            warnings.append(f"🚨 Pressure tactic: '{phrase}'")
            break
    
    # Money promises
    money = ['won', 'winner', 'prize', 'million', 'lottery', 'inheritance', 'jackpot', 'congratulations']
    for word in money:
        if word in text_lower:
            risk_score += 25
            warnings.append(f"💰 Too-good-to-be-true: '{word}'")
            break
    
    # Personal info requests
    info = ['verify your', 'confirm your', 'social security', 'bank account', 
            'credit card', 'password', 'cvv', 'pin number']
    for phrase in info:
        if phrase in text_lower:
            risk_score += 30
            warnings.append(f"🔐 Requests sensitive info: '{phrase}'")
            break
    
    # Threats
    threats = ['suspended', 'locked', 'terminated', 'legal action', 'arrest', 'blocked', 'closed']
    for word in threats:
        if word in text_lower:
            risk_score += 20
            warnings.append(f"⚡ Threatening: '{word}'")
            break
    
    # Links in message
    links = re.findall(r'http[s]?://[^\s]+', text)
    if links:
        risk_score += 15
        warnings.append(f"🔗 Contains {len(links)} link(s)")
    
    # Impersonation
    brands = ['microsoft', 'apple', 'amazon', 'paypal', 'bank', 'irs', 'fbi', 'government']
    for brand in brands:
        if brand in text_lower:
            risk_score += 15
            warnings.append(f"🎭 May impersonate: '{brand.title()}'")
            break
    
    # Excessive punctuation
    if text.count('!') > 3 or text.count('?') > 3:
        risk_score += 10
        warnings.append("❗ Excessive punctuation")
    
    return {'risk_score': min(risk_score, 100), 'warnings': warnings}


# ============== API ENDPOINTS ==============

@app.route('/api/check-url', methods=['POST'])
def check_url():
    """Endpoint to check URLs"""
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    print(f"\n🔍 Checking URL: {url}")
    
    # Check with Google
    google_result = check_url_with_google(url)
    
    # Analyze structure
    structure_result = analyze_url_structure(url)
    
    # Combine scores
    total_risk = google_result.get('risk_score', 0) + structure_result['risk_score']
    total_risk = min(total_risk, 100)
    
    # Determine level
    if total_risk >= 70:
        risk_level = "HIGH"
        status = "🔴 DANGEROUS"
    elif total_risk >= 40:
        risk_level = "MEDIUM"
        status = "🟡 SUSPICIOUS"
    else:
        risk_level = "LOW"
        status = "🟢 SAFE"
    
    # Generate explanation
    if google_result.get('threat_found'):
        explanation = f"🚨 **CRITICAL THREAT DETECTED!**\n\nGoogle Safe Browsing flagged this as: **{google_result.get('threat_type')}**\n\nThis is a confirmed malicious link. DO NOT CLICK!"
    elif total_risk >= 70:
        explanation = "⚠️ **HIGH RISK - Strong scam indicators detected!**\n\nMultiple red flags found. Do NOT click this link or enter any information."
    elif total_risk >= 40:
        explanation = "⚠️ **MEDIUM RISK - Suspicious characteristics detected.**\n\nProceed with extreme caution. Verify the source before clicking."
    else:
        explanation = "✅ **LOW RISK - This URL appears relatively safe.**\n\nNo major threats detected, but always stay vigilant online."
    
    result = {
        'risk_score': total_risk,
        'risk_level': risk_level,
        'status': status,
        'explanation': explanation,
        'warning_signs': structure_result['warnings'],
        'google_threat': google_result.get('threat_type', None)
    }
    
    # Log this scan to database
    log_scan('URL', risk_level, total_risk)
    
    print(f"✅ Result: {risk_level} ({total_risk}%)")
    return jsonify(result)


@app.route('/api/check-text', methods=['POST'])
def check_text():
    """Endpoint to check messages/emails"""
    data = request.json
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    
    print(f"\n📧 Checking text: {text[:50]}...")
    
    # Analyze text
    result = analyze_text_for_scams(text)
    risk_score = result['risk_score']
    
    # Determine level
    if risk_score >= 70:
        risk_level = "HIGH"
        status = "🔴 SCAM DETECTED"
        explanation = "🚨 **HIGH RISK - This message shows strong scam indicators!**\n\nThis appears to be a scam. Do NOT respond, click links, or share information."
    elif risk_score >= 40:
        risk_level = "MEDIUM"
        status = "🟡 SUSPICIOUS"
        explanation = "⚠️ **MEDIUM RISK - Suspicious elements detected.**\n\nExercise extreme caution. Verify the sender through official channels."
    else:
        risk_level = "LOW"
        status = "🟢 APPEARS SAFE"
        explanation = "✅ **LOW RISK - No major scam indicators.**\n\nThis message appears relatively safe, but always verify unexpected requests."
    
    tips = [
        "Never share passwords or PINs",
        "Verify sender through official channels",
        "Be skeptical of urgent requests",
        "Don't click suspicious links"
    ]
    
    response = {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'status': status,
        'explanation': explanation,
        'warning_signs': result['warnings'],
        'safety_tips': tips
    }
    
    # Log this scan to database
    log_scan('TEXT', risk_level, risk_score)
    
    print(f"✅ Result: {risk_level} ({risk_score}%)")
    return jsonify(response)


@app.route('/api/check-email', methods=['POST'])
def check_email():
    """Endpoint to check emails for phishing/scams"""
    data = request.json
    
    # Get email parts
    sender = data.get('email', '').lower()
    subject = data.get('subject', '')
    body = data.get('body', '')
    
    if not sender and not body:
        return jsonify({'error': 'No email data provided'}), 400
    
    print(f"\n📧 Checking email from: {sender}")
    
    risk_score = 0
    warnings = []
    
    # --- SENDER ANALYSIS ---
    
    # Check for suspicious sender domains
    suspicious_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
    trusted_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'bank', 'irs']
    
    # If sender claims to be from a major company but uses free email
    for brand in trusted_brands:
        if brand in sender and any(domain in sender for domain in suspicious_domains):
            risk_score += 40
            warnings.append(f"🚨 Suspicious: Claims to be {brand.title()} but uses free email service")
            break
    
    # Check for misspelled domains (typosquatting)
    typosquat_patterns = ['paypa1', 'amaz0n', 'micros0ft', 'app1e', 'bankof']
    for pattern in typosquat_patterns:
        if pattern in sender:
            risk_score += 50
            warnings.append(f"🚨 CRITICAL: Misspelled domain detected - likely phishing!")
            break
    
    # --- SUBJECT ANALYSIS ---
    
    subject_lower = subject.lower()
    
    # Urgent/threatening subjects
    urgent_words = ['urgent', 'immediate action', 'suspend', 'verify now', 
                    'confirm immediately', 'expire', 'locked', 'security alert']
    for word in urgent_words:
        if word in subject_lower:
            risk_score += 20
            warnings.append(f"⚡ Urgent pressure tactic in subject: '{word}'")
            break
    
    # Too-good-to-be-true subjects
    prize_words = ['won', 'winner', 'prize', 'free', 'congratulations', '$']
    for word in prize_words:
        if word in subject_lower:
            risk_score += 25
            warnings.append(f"💰 Suspicious prize/money claim: '{word}'")
            break
    
    # --- BODY ANALYSIS ---
    
    # Combine body analysis with existing text analyzer
    body_analysis = analyze_text_for_scams(body)
    risk_score += body_analysis['risk_score']
    warnings.extend(body_analysis['warnings'])
    
    # Additional email-specific checks
    
    # Generic greetings (legit companies use your name)
    generic = ['dear customer', 'dear user', 'dear member', 'valued customer']
    if any(g in body.lower() for g in generic):
        risk_score += 15
        warnings.append("👤 Generic greeting (legit companies use your name)")
    
    # Requests to click links
    if 'click here' in body.lower() or 'click below' in body.lower():
        risk_score += 15
        warnings.append("🔗 Suspicious: Asks you to 'click here'")
    
    # Attachment warnings
    if 'attachment' in body.lower() or 'attached file' in body.lower():
        risk_score += 20
        warnings.append("📎 Caution: Email mentions attachments (could contain malware)")
    
    # Poor grammar/spelling (common in scams)
    grammar_issues = body.count('..') + body.count('!!') + body.count('??')
    if grammar_issues > 2:
        risk_score += 10
        warnings.append("📝 Poor formatting/grammar (common in scams)")
    
    # Cap risk score
    risk_score = min(risk_score, 100)
    
    # --- DETERMINE RISK LEVEL ---
    
    if risk_score >= 70:
        risk_level = "HIGH"
        status = "🔴 PHISHING DETECTED"
        explanation = "🚨 **DANGER! This email shows strong phishing indicators!**\n\nThis is very likely a scam email. DO NOT:\n- Click any links\n- Download attachments\n- Reply with personal information\n- Forward it to others\n\nDelete this email immediately and report it as phishing."
    elif risk_score >= 40:
        risk_level = "MEDIUM"
        status = "🟡 SUSPICIOUS"
        explanation = "⚠️ **CAUTION: This email has suspicious characteristics.**\n\nBefore taking any action:\n- Verify the sender through official channels\n- Check the sender's email address carefully\n- Don't click links - visit the company's website directly\n- Contact the company through their official support"
    else:
        risk_level = "LOW"
        status = "🟢 APPEARS LEGITIMATE"
        explanation = "✅ **This email appears relatively safe.**\n\nNo major red flags detected, but remember:\n- Always verify unexpected requests\n- Never share passwords via email\n- When in doubt, contact the sender directly through official channels"
    
    # Safety tips specific to emails
    email_tips = [
        "Never click links in unexpected emails",
        "Verify sender's email address carefully (look for misspellings)",
        "Hover over links to see real destination before clicking",
        "Companies never ask for passwords via email",
        "When in doubt, contact the company directly using official contact info"
    ]
    
    response = {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'status': status,
        'explanation': explanation,
        'warning_signs': warnings,
        'safety_tips': email_tips,
        'sender_analysis': f"Sender: {sender}" if sender else None
    }
    
    # Log this scan to database
    log_scan('EMAIL', risk_level, risk_score)
    
    print(f"✅ Email Result: {risk_level} ({risk_score}%)")
    return jsonify(response)


@app.route('/api/stats', methods=['GET'])
def stats():
    """Get statistics from database"""
    stats_data = get_stats()
    return jsonify(stats_data)


@app.route('/api/quiz', methods=['GET'])
def quiz():
    """Get cybersecurity quiz questions"""
    questions = [
        {
            "id": 1,
            "question": "A company emails you asking to verify your password. What should you do?",
            "options": [
                "Reply with your password",
                "Click the link and verify",
                "Ignore and contact company directly",
                "Forward to friends for advice"
            ],
            "correct": 2,
            "explanation": "Legitimate companies NEVER ask for passwords via email. Always contact them through official channels."
        },
        {
            "id": 2,
            "question": "You receive a message saying you won a prize you never entered. This is likely:",
            "options": [
                "A legitimate prize",
                "A phishing scam",
                "A mistake",
                "Good luck"
            ],
            "correct": 1,
            "explanation": "Prize scams are very common. If you didn't enter, you didn't win. These are designed to steal your information."
        },
        {
            "id": 3,
            "question": "What makes a URL suspicious?",
            "options": [
                "It uses HTTPS",
                "It's from a .com domain",
                "It uses an IP address instead of a domain name",
                "It's short"
            ],
            "correct": 2,
            "explanation": "Legitimate websites use domain names. IP addresses in URLs are often used by scammers to hide their identity."
        },
        {
            "id": 4,
            "question": "An email says 'URGENT: Your account will be closed in 24 hours!' What is this?",
            "options": [
                "Important security alert",
                "Pressure tactic to make you act without thinking",
                "Standard company procedure",
                "Technical error"
            ],
            "correct": 1,
            "explanation": "Creating urgency is a common scam tactic. Legitimate companies give you time and don't threaten account closure via email."
        },
        {
            "id": 5,
            "question": "Best way to check if an email is legitimate:",
            "options": [
                "Click the links to see where they go",
                "Reply and ask if it's real",
                "Contact the company using official contact info from their website",
                "Check if it has a logo"
            ],
            "correct": 2,
            "explanation": "Always verify through official channels you find yourself, not through links or contact info in the suspicious email."
        }
    ]
    return jsonify(questions)


@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'message': 'AegisAI API is running',
        'api_key_present': bool(GOOGLE_API_KEY)
    })


if __name__ == '__main__':
    print("\n" + "="*50)
    print("🛡️  AEGISAI BACKEND STARTING")
    print("="*50)
    print(f"📡 API running on: http://localhost:5000")
    print(f"🔑 Google API Key: {'✅ Loaded' if GOOGLE_API_KEY else '❌ Missing'}")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)