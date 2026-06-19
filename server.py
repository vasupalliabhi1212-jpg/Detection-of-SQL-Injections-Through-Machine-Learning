import pickle
import re
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_cors import CORS
from flask import Flask, request, jsonify, render_template
from sklearn.preprocessing import LabelEncoder
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Suppress all warnings and debug output
import warnings
import logging
warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)

print("🚀 Starting Attack Predictor Server...")
print(f"📧 Email config: {os.getenv('EMAIL_USER')}@{os.getenv('EMAIL_HOST')}:{os.getenv('EMAIL_PORT')}")
print(f"🔑 Password loaded: {'Yes' if os.getenv('EMAIL_PASSWORD') else 'No'}")

# Suppress sklearn warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# Load model and vectorizer
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, "random_forest_model.pkl"), "rb") as model_file:
    loaded_model = pickle.load(model_file)

with open(os.path.join(BASE_DIR, "tfidf_vectorizer.pkl"), "rb") as vectorizer_file:
    loaded_vectorizer = pickle.load(vectorizer_file)

# Load label encoder
label_encoder = LabelEncoder()
label_encoder.classes_ = pickle.load(open(os.path.join(BASE_DIR, "label_encoder.pkl"), "rb"))

# Flask App
app = Flask(__name__)
CORS(app)

# Suppress all Flask and Werkzeug output
import logging
logging.getLogger('werkzeug').disabled = True
log = logging.getLogger('werkzeug')
log.setLevel(logging.CRITICAL)

print("📋 Registering Flask routes...")

# Initialize SQLite DB for users and alerts
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Create users table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    
    # Create alerts table for storing attack detections
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        user_email TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    # Create login event records for tracking suspicious login behavior
    c.execute('''CREATE TABLE IF NOT EXISTS login_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        user_email TEXT,
        event_type TEXT NOT NULL,
        details TEXT,
        event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    conn.commit()
    conn.close()

init_db()

# Email configuration - RECOMMENDED: Use environment variables for security
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USER = os.getenv("EMAIL_USER", "your-email@gmail.com")  # Set EMAIL_USER env var
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "your-app-password")  # Set EMAIL_PASSWORD env var

def send_attack_notification(user_email, attack_type, payload):
    try:
        print(f"Attempting to send email notification to: {user_email}")
        print(f"Attack type: {attack_type}")
        print(f"Payload: {payload}")

        msg = MIMEMultipart()
        msg['From'] = f"Attack Predictor <{EMAIL_USER}>"
        msg['To'] = user_email
        msg['Subject'] = f'🚨 Attack Detection Alert - {attack_type.upper()}'

        detection_time = re.sub(r'\.\d+', '', str(datetime.datetime.now()))

        body = f"""
        <html>
        <body>
            <h2>🚨 Security Alert: Attack Detected!</h2>
            <p><strong>Attack Type:</strong> {attack_type.upper()}</p>
            <p><strong>Suspicious Payload:</strong> <code>{payload}</code></p>
            <p><strong>Detection Time:</strong> {detection_time}</p>
            <br>
            <p>This is an automated security notification from the Attack Predictor system.</p>
            <p>Please review this activity and take appropriate action if necessary.</p>
            <br>
            <p><em>Stay safe,<br>Attack Predictor Security Team</em></p>
         </body>
        </html>
        """

        msg.attach(MIMEText(body, 'html'))

        print("Connecting to SMTP server...")
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.set_debuglevel(1)
        server.ehlo()
        server.starttls()
        server.ehlo()

        print("Logging into SMTP server...")
        server.login(EMAIL_USER, EMAIL_PASSWORD)

        print("Sending email...")
        server.send_message(msg)
        server.quit()

        print(f"✅ Email notification sent successfully to {user_email}")
        return True
    except smtplib.SMTPAuthenticationError as auth_err:
        print(f"❌ SMTP authentication failed: {auth_err}")
        return False
    except smtplib.SMTPException as smtp_err:
        print(f"❌ SMTP error while sending email: {smtp_err}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error while sending email: {e}")
        return False


print("📧 Registering test email endpoint...")
@app.route('/api/test-email', methods=['POST'])
def test_email():
    data = request.get_json() or {}
    target = data.get('email')
    print(f"🔍 TEST EMAIL REQUEST: target={target}")
    if not target:
        return jsonify({'error': 'Please provide an email in request body {"email": "you@example.com"}'}), 400

    print(f"📧 Attempting to send test email to: {target}")
    sent = send_attack_notification(target, 'test_notification', 'This is a test email from Attack Predictor')
    print(f"📧 Email send result: {sent}")
    if sent:
        return jsonify({'message': f'Email test message sent to {target} (check your inbox/spam).'}), 200
    else:
        return jsonify({'error': 'Failed to send test email. Check server logs for SMTP details.'}), 500


def clean_text(text):
    text = text.lower()
    text = re.sub(r'[^\w\s]', '', text)
    return text

def predict_attack(payload):
    cleaned_payload = clean_text(payload)
    payload_tfidf = loaded_vectorizer.transform([cleaned_payload])
    prediction = loaded_model.predict(payload_tfidf)
    return label_encoder.inverse_transform(prediction)[0]


def detect_login_attack(password):
    """Detect suspicious injection-like patterns in login fields"""
    if not password:
        return False, ""

    # Common attack patterns in password text (SQLi/XSS/command injection heuristics)
    injector_patterns = [
        r"(\bselect\b.*\bfrom\b|\bunion\b.*\bselect\b|--|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b)",
        r"(<script|javascript:|onerror=|onload=|alert\(|prompt\(|<img.*src=|onclick=)",
        r"(\.|\.\.|/etc/passwd|proc/self/environ|win\.ini|\$\{|`[^`]*`|;\s*sh)"
    ]

    for pat in injector_patterns:
        if re.search(pat, password, re.IGNORECASE):
            return True, f"Suspicious pattern detected in password: {pat}"

    if len(password) < 6:
        return True, "Weak/short password (less than 6 characters)"

    return False, ""


def record_login_event(user_id, user_email, event_type, details=""):
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''INSERT INTO login_events (user_id, user_email, event_type, details) VALUES (?, ?, ?, ?)''',
                  (user_id, user_email, event_type, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error recording login event: {e}")


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/signup")
def signup_page():
    return render_template("signup.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/welcome")
def welcome():
    return render_template("shopping.html")

@app.route("/shopping")
def shopping():
    return render_template("shopping.html")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    payload = data.get("payload", "")
    user_email = data.get("user_email", "")
    user_id = data.get("user_id", None)
    
    print(f"Prediction request - Payload: {payload}, User Email: {user_email}")
    
    if not payload:
        return jsonify({"error": "No payload provided"}), 400
    
    prediction = predict_attack(payload)
    print(f"Prediction result: {prediction}")
    
    # Save alert to database if attack is detected
    if prediction != 'norm':
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('''INSERT INTO alerts (user_id, user_email, attack_type, payload) 
                        VALUES (?, ?, ?, ?)''',
                     (user_id, user_email, prediction, payload))
            conn.commit()
            conn.close()
            print(f"Alert saved to database: {prediction}")
        except Exception as e:
            print(f"Error saving alert to database: {e}")
    
    # Send email notification if attack is detected and user email is provided
    if prediction != 'norm' and user_email:
        print(f"Attack detected! Sending notification to {user_email}")
        notification_sent = send_attack_notification(user_email, prediction, payload)
        print(f"Email notification status: {'Success' if notification_sent else 'Failed'}")
    else:
        print(f"No notification sent. Attack: {prediction != 'norm'}, Email provided: {bool(user_email)}")
    
    return jsonify({"attack_type": prediction})

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    
    if not username or not email or not password or not confirm_password:
        return jsonify({'error': 'All fields are required'}), 400
    
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400
    
    hashed_password = generate_password_hash(password)
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User created successfully'}), 201
    except sqlite3.IntegrityError as e:
        if 'username' in str(e):
            return jsonify({'error': 'Username already exists'}), 409
        elif 'email' in str(e):
            return jsonify({'error': 'Email already exists'}), 409
        else:
            return jsonify({'error': 'Registration failed'}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    # Detect suspicious login credentials and log it.
    suspicious, reason = detect_login_attack(password)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username, password FROM users WHERE email = ?', (email,))
    row = c.fetchone()
    conn.close()

    if not row:
        if suspicious:
            send_attack_notification(email, 'suspicious_login_attempt', f'{reason}. User does not exist.')
        return jsonify({'error': 'User not found. Please sign up first.'}), 401

    user_id, username, hashed_password = row

    # Record suspicious login attempt for analysis
    if suspicious:
        record_login_event(user_id, email, 'suspicious_login', reason)
        send_attack_notification(email, 'suspicious_login_attempt', f'{reason}. Please change your password immediately.')

    if not check_password_hash(hashed_password, password):
        record_login_event(user_id, email, 'failed_login', 'Wrong password')

        # if multiple failed attempts in last hour, notify user
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("""SELECT COUNT(*) FROM login_events 
                     WHERE user_email = ? AND event_type = 'failed_login' 
                     AND event_time >= datetime('now','-1 hour')""", (email,))
        failed_count = c.fetchone()[0]
        conn.close()

        if failed_count >= 3:
            send_attack_notification(email, 'multiple_failed_login',
                f'We detected {failed_count} failed login attempts in the past hour. We recommend changing your password.')

        return jsonify({'error': 'Incorrect password.'}), 401

    record_login_event(user_id, email, 'successful_login', 'Password verified')

    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user_id,
            'username': username,
            'email': email
        }
    }), 200

# Debug endpoint: list all users (for development only)
@app.route('/users', methods=['GET'])
def list_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users')
    users = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify({'users': users})

# Dashboard Metrics Endpoint
@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Total alerts
        c.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = c.fetchone()[0]
        
        # Attacks by type
        c.execute('SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type')
        attacks_by_type = dict(c.fetchall())
        
        # Total users
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        
        # Alerts today
        c.execute('''SELECT COUNT(*) FROM alerts 
                     WHERE DATE(detection_time) = DATE('now')''')
        alerts_today = c.fetchone()[0]
        
        # Alerts this week
        c.execute('''SELECT COUNT(*) FROM alerts 
                     WHERE detection_time >= datetime('now', '-7 days')''')
        alerts_week = c.fetchone()[0]
        
        # Most active attack type
        c.execute('''SELECT attack_type, COUNT(*) as count FROM alerts 
                     GROUP BY attack_type ORDER BY count DESC LIMIT 1''')
        most_common = c.fetchone()
        most_common_attack = most_common[0] if most_common else 'None'
        
        conn.close()
        
        return jsonify({
            'total_alerts': total_alerts,
            'attacks_by_type': attacks_by_type,
            'total_users': total_users,
            'alerts_today': alerts_today,
            'alerts_week': alerts_week,
            'most_common_attack': most_common_attack
        }), 200
    except Exception as e:
        print(f"Error retrieving metrics: {e}")
        return jsonify({'error': str(e)}), 500

# Dashboard Alerts Endpoint - Get recent alerts
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    try:
        limit = request.args.get('limit', 10, type=int)
        user_email = request.args.get('email', None)
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        if user_email:
            # Get alerts for specific user
            c.execute('''SELECT id, user_email, attack_type, payload, detection_time 
                        FROM alerts WHERE user_email = ? 
                        ORDER BY detection_time DESC LIMIT ?''',
                     (user_email, limit))
        else:
            # Get all recent alerts
            c.execute('''SELECT id, user_email, attack_type, payload, detection_time 
                        FROM alerts ORDER BY detection_time DESC LIMIT ?''',
                     (limit,))
        
        alerts = c.fetchall()
        conn.close()
        
        alerts_list = []
        for alert in alerts:
            alerts_list.append({
                'id': alert[0],
                'user_email': alert[1],
                'attack_type': alert[2],
                'payload': alert[3][:100],  # Limit payload display
                'detection_time': alert[4]
            })
        
        return jsonify({'alerts': alerts_list}), 200
    except Exception as e:
        print(f"Error retrieving alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/login_events', methods=['GET'])
def get_login_events():
    try:
        limit = request.args.get('limit', 10, type=int)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''SELECT id, user_email, event_type, details, event_time FROM login_events ORDER BY event_time DESC LIMIT ?''', (limit,))
        rows = c.fetchall()
        conn.close()

        events = []
        for row in rows:
            events.append({
                'id': row[0],
                'user_email': row[1],
                'event_type': row[2],
                'details': row[3],
                'event_time': row[4]
            })

        return jsonify({'login_events': events}), 200
    except Exception as e:
        print(f"Error retrieving login events: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    print("\n" + "="*60)
    print("🎯 CYBERSECURITY THREAT DETECTION SYSTEM")
    print("="*60)
    print("✅ Server Status: Starting...")
    print("✅ Database: SQLite initialized")
    print("✅ ML Models: Loaded successfully")
    print("✅ Email System: Configured")
    print("✅ Routes: All endpoints registered")
    print("="*60)
    print("🌐 ACCESS YOUR APPLICATION AT:")
    print("   📱 Local:   http://localhost:5000")
    print("   🌍 Network: http://192.168.29.102:5000")
    print("="*60)
    print("📋 AVAILABLE PAGES:")
    print("   🏠 Home:     http://localhost:5000/")
    print("   📊 Dashboard: http://localhost:5000/dashboard")
    print("   🔐 Login:    http://localhost:5000/login")
    print("   📝 Signup:   http://localhost:5000/signup")
    print("   ℹ️  About:    http://localhost:5000/about")
    print("="*60)
    print("🛡️  SECURITY FEATURES:")
    print("   • Real-time attack detection")
    print("   • Email notifications")
    print("   • User authentication")
    print("   • Threat intelligence dashboard")
    print("="*60)
    print("Press Ctrl+C to stop the server")
    print("="*60 + "\n")

    app.run(host="0.0.0.0", port=5000, debug=False)
