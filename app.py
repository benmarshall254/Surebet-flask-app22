from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import json
import secrets
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Generate a secure secret key if not provided
if not os.environ.get('FLASK_SECRET_KEY'):
    # Generate a random secret key for development
    app.secret_key = secrets.token_hex(32)
    print("WARNING: Using generated secret key. Set FLASK_SECRET_KEY environment variable for production!")
else:
    app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# Enhanced security configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'  # Only HTTPS in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Session expires after 2 hours

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize DB with better error handling
def init_db():
    try:
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        
        # Enable foreign keys
        cursor.execute('PRAGMA foreign_keys = ON')
        
        # Create tables with better constraints
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                team1 TEXT NOT NULL,
                team2 TEXT NOT NULL,
                prediction TEXT NOT NULL,
                odds TEXT,
                confidence INTEGER CHECK(confidence >= 0 AND confidence <= 100),
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'won', 'lost')),
                result TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS yesterday_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                team1 TEXT NOT NULL,
                team2 TEXT NOT NULL,
                score TEXT NOT NULL,
                prediction TEXT,
                result TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Create default admin user if none exists
        cursor.execute('SELECT COUNT(*) FROM admin_users')
        if cursor.fetchone()[0] == 0:
            # Use a stronger default password in production
            default_password = os.environ.get('ADMIN_DEFAULT_PASSWORD', 'admin123')
            password_hash = generate_password_hash(default_password)
            cursor.execute('''
                INSERT INTO admin_users (username, password_hash, created_at)
                VALUES (?, ?, ?)
            ''', ('admin', password_hash, datetime.now().isoformat()))
            logger.warning(f"Created default admin user with password: {default_password}")
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
        
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session.get('admin_logged_in'):
            logger.warning(f"Unauthorized access attempt to {request.endpoint} from {request.remote_addr}")
            return redirect(url_for('admin_login'))
        
        # Check session timeout
        if 'login_time' in session:
            if datetime.now() - datetime.fromisoformat(session['login_time']) > timedelta(hours=2):
                session.clear()
                flash('Session expired. Please login again.')
                return redirect(url_for('admin_login'))
        
        return f(*args, **kwargs)
    return decorated_function

def check_account_lockout(username):
    """Check if account is locked due to failed attempts"""
    conn = sqlite3.connect('surebet.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT failed_attempts, locked_until 
        FROM admin_users 
        WHERE username = ?
    ''', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        failed_attempts, locked_until = result
        if locked_until:
            lock_time = datetime.fromisoformat(locked_until)
            if datetime.now() < lock_time:
                return True, lock_time
        if failed_attempts >= 5:  # Lock after 5 failed attempts
            return True, None
    return False, None

def update_failed_attempts(username, success=False):
    """Update failed login attempts counter"""
    conn = sqlite3.connect('surebet.db')
    cursor = conn.cursor()
    
    if success:
        cursor.execute('''
            UPDATE admin_users 
            SET failed_attempts = 0, locked_until = NULL, last_login = ?
            WHERE username = ?
        ''', (datetime.now().isoformat(), username))
    else:
        cursor.execute('''
            UPDATE admin_users 
            SET failed_attempts = failed_attempts + 1,
                locked_until = CASE 
                    WHEN failed_attempts >= 4 THEN ? 
                    ELSE locked_until 
                END
            WHERE username = ?
        ''', ((datetime.now() + timedelta(minutes=30)).isoformat(), username))
    
    conn.commit()
    conn.close()

# Input validation helper
def validate_input(data, required_fields):
    """Validate required fields and basic input sanitization"""
    if not data:
        return False, "No data provided"
    
    for field in required_fields:
        if field not in data or not data[field] or not str(data[field]).strip():
            return False, f"Missing required field: {field}"
    
    return True, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')
        
        # Check account lockout
        is_locked, lock_time = check_account_lockout(username)
        if is_locked:
            if lock_time:
                flash(f'Account locked until {lock_time.strftime("%H:%M")}')
            else:
                flash('Account locked due to too many failed attempts')
            return render_template('login.html')
        
        try:
            conn = sqlite3.connect('surebet.db')
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (username,))
            row = cursor.fetchone()
            conn.close()
            
            if row and check_password_hash(row[0], password):
                session.permanent = True
                session['admin_logged_in'] = True
                session['admin_username'] = username
                session['login_time'] = datetime.now().isoformat()
                update_failed_attempts(username, success=True)
                logger.info(f"Successful login for user: {username} from {request.remote_addr}")
                return redirect(url_for('admin_dashboard'))
            else:
                update_failed_attempts(username, success=False)
                logger.warning(f"Failed login attempt for user: {username} from {request.remote_addr}")
                flash('Invalid credentials')
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Login error occurred')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/yesterday.html')
def yesterday():
    return render_template('yesterday.html')

@app.route('/today.html')
def today():
    return render_template('today.html')

@app.route('/admin.html')
def admin_login():
    # Redirect if already logged in
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    return render_template('admin.html')

@app.route('/admin-dashboard.html')
@login_required  # This was missing before!
def admin_dashboard_html():
    return render_template('admin-dashboard.html')

@app.route('/analytics', methods=['POST'])
@limiter.limit("10 per minute")
def analytics():
    try:
        data = request.get_json()
        if data and data.get('page'):
            # Validate page parameter
            page = str(data.get('page', ''))[:100]  # Limit length
            
            conn = sqlite3.connect('surebet.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO analytics (page, timestamp, ip_address, user_agent)
                VALUES (?, ?, ?, ?)
            ''', (
                page,
                datetime.now().isoformat(),
                request.remote_addr,
                str(request.user_agent)[:500]  # Limit user agent length
            ))
            conn.commit()
            conn.close()
            return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Analytics error: {e}")
    return jsonify({'status': 'error'}), 400

@app.route('/admin/login', methods=['POST'])
@limiter.limit("3 per minute")  # Stricter rate limiting for admin login
def admin_login_post():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        flash('Username and password are required')
        return redirect(url_for('admin_login'))
    
    # Check account lockout
    is_locked, lock_time = check_account_lockout(username)
    if is_locked:
        if lock_time:
            flash(f'Account locked until {lock_time.strftime("%H:%M")}')
        else:
            flash('Account locked due to too many failed attempts')
        return redirect(url_for('admin_login'))
    
    try:
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row and check_password_hash(row[0], password):
            session.permanent = True
            session['admin_logged_in'] = True
            session['admin_username'] = username
            session['login_time'] = datetime.now().isoformat()
            update_failed_attempts(username, success=True)
            logger.info(f"Successful admin login for user: {username} from {request.remote_addr}")
            return redirect(url_for('admin_dashboard'))
        else:
            update_failed_attempts(username, success=False)
            logger.warning(f"Failed admin login attempt for user: {username} from {request.remote_addr}")
            flash('Invalid credentials')
            
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        flash('Login error occurred')
    
    return redirect(url_for('admin_login'))

@app.route('/admin/logout')
def admin_logout():
    username = session.get('admin_username', 'unknown')
    session.clear()
    logger.info(f"User {username} logged out from {request.remote_addr}")
    flash('Successfully logged out')
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/api/today-predictions')
def get_today_predictions():
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT team1, team2, prediction, odds, confidence, status
            FROM predictions 
            WHERE date = ?
            ORDER BY created_at DESC
            LIMIT 50
        ''', (today,))
        predictions = [{
            'team1': str(row[0])[:50],  # Limit field lengths
            'team2': str(row[1])[:50],
            'prediction': str(row[2])[:100],
            'odds': str(row[3])[:20] if row[3] else '',
            'confidence': int(row[4]) if row[4] else 0,
            'status': str(row[5])[:20] if row[5] else 'pending'
        } for row in cursor.fetchall()]
        conn.close()
        return jsonify(predictions)
    except Exception as e:
        logger.error(f"Error fetching predictions: {e}")
        return jsonify({'error': 'Failed to fetch predictions'}), 500

@app.route('/api/yesterday-scores')
def get_yesterday_scores():
    try:
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT team1, team2, score, prediction, result
            FROM yesterday_scores 
            WHERE date = ?
            ORDER BY created_at DESC
            LIMIT 50
        ''', (yesterday,))
        scores = [{
            'team1': str(row[0])[:50],
            'team2': str(row[1])[:50],
            'score': str(row[2])[:20],
            'prediction': str(row[3])[:100] if row[3] else '',
            'result': str(row[4])[:20] if row[4] else ''
        } for row in cursor.fetchall()]
        conn.close()
        return jsonify(scores)
    except Exception as e:
        logger.error(f"Error fetching scores: {e}")
        return jsonify({'error': 'Failed to fetch scores'}), 500

@app.route('/admin/api/add-prediction', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def add_prediction():
    try:
        data = request.get_json()
        valid, error = validate_input(data, ['team1', 'team2', 'prediction'])
        if not valid:
            return jsonify({'error': error}), 400
        
        # Validate confidence range
        confidence = data.get('confidence', 80)
        if not isinstance(confidence, int) or confidence < 0 or confidence > 100:
            confidence = 80
        
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO predictions (date, team1, team2, prediction, odds, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('date', datetime.now().strftime('%Y-%m-%d')),
            str(data['team1'])[:50],
            str(data['team2'])[:50],
            str(data['prediction'])[:100],
            str(data.get('odds', ''))[:20],
            confidence,
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
        
        logger.info(f"Prediction added by {session.get('admin_username')}: {data['team1']} vs {data['team2']}")
        return jsonify({'status': 'success'})
        
    except Exception as e:
        logger.error(f"Error adding prediction: {e}")
        return jsonify({'error': 'Failed to add prediction'}), 500

@app.route('/admin/api/add-score', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def add_score():
    try:
        data = request.get_json()
        valid, error = validate_input(data, ['team1', 'team2', 'score'])
        if not valid:
            return jsonify({'error': error}), 400
        
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO yesterday_scores (date, team1, team2, score, prediction, result, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('date', (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')),
            str(data['team1'])[:50],
            str(data['team2'])[:50],
            str(data['score'])[:20],
            str(data.get('prediction', ''))[:100],
            str(data.get('result', ''))[:20],
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
        
        logger.info(f"Score added by {session.get('admin_username')}: {data['team1']} vs {data['team2']} - {data['score']}")
        return jsonify({'status': 'success'})
        
    except Exception as e:
        logger.error(f"Error adding score: {e}")
        return jsonify({'error': 'Failed to add score'}), 500

@app.route('/admin/api/analytics')
@login_required
def get_analytics():
    try:
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM analytics')
        total_visits = cursor.fetchone()[0]
        
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute('SELECT COUNT(*) FROM analytics WHERE DATE(timestamp) = ?', (today,))
        today_visits = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT page, COUNT(*) as count 
            FROM analytics 
            GROUP BY page 
            ORDER BY count DESC
            LIMIT 10
        ''')
        page_stats = cursor.fetchall()
        
        cursor.execute('''
            SELECT page, timestamp, ip_address 
            FROM analytics 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')
        recent_visits = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'total_visits': total_visits,
            'today_visits': today_visits,
            'page_stats': [{'page': row[0], 'count': row[1]} for row in page_stats],
            'recent_visits': [{'page': row[0], 'timestamp': row[1], 'ip': row[2]} for row in recent_visits]
        })
        
    except Exception as e:
        logger.error(f"Error fetching analytics: {e}")
        return jsonify({'error': 'Failed to fetch analytics'}), 500

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

if __name__ == '__main__':
    init_db()
    
    # Security warning for development
    if app.config.get('DEBUG'):
        logger.warning("Running in DEBUG mode. Do not use in production!")
    
    app.run(
        debug=os.environ.get('FLASK_ENV') != 'production',
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000))
    )
