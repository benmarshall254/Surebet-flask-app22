from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import json

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'replace-this-with-a-long-random-string-in-production')

# Secure session cookies
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Set to False if not using HTTPS in development
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Optional: Secure headers (uncomment if using Flask-Talisman)
# from flask_talisman import Talisman
# Talisman(app)

# Initialize DB
def init_db():
    conn = sqlite3.connect('surebet.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
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
            confidence INTEGER,
            status TEXT DEFAULT 'pending',
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
    cursor.execute('SELECT COUNT(*) FROM admin_users')
    if cursor.fetchone()[0] == 0:
        password_hash = generate_password_hash('admin123')  # Use werkzeug
        cursor.execute('''
            INSERT INTO admin_users (username, password_hash, created_at)
            VALUES (?, ?, ?)
        ''', ('admin', password_hash, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()
        if row and check_password_hash(row[0], password):
            session['admin_logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard')
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
    return render_template('admin.html')

@app.route('/admin-dashboard.html')
def admin_dashboard_html():
    return render_template('admin-dashboard.html')

@app.route('/analytics', methods=['POST'])
def analytics():
    try:
        data = request.get_json()
        if data:
            conn = sqlite3.connect('surebet.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO analytics (page, timestamp, ip_address, user_agent)
                VALUES (?, ?, ?, ?)
            ''', (
                data.get('page', ''),
                data.get('timestamp', datetime.now().isoformat()),
                request.remote_addr,
                request.user_agent.string
            ))
            conn.commit()
            conn.close()
            return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Analytics error: {e}")
    return jsonify({'status': 'error'}), 400

@app.route('/admin/login', methods=['POST'])
def admin_login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    if username and password:
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()
        if row and check_password_hash(row[0], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials')
    return redirect(url_for('admin_login'))

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/api/today-predictions')
def get_today_predictions():
    today = datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect('surebet.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT team1, team2, prediction, odds, confidence, status
        FROM predictions 
        WHERE date = ?
        ORDER BY created_at DESC
    ''', (today,))
    predictions = [{
        'team1': row[0], 'team2': row[1], 'prediction': row[2],
        'odds': row[3], 'confidence': row[4], 'status': row[5]
    } for row in cursor.fetchall()]
    conn.close()
    return jsonify(predictions)

@app.route('/api/yesterday-scores')
def get_yesterday_scores():
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    conn = sqlite3.connect('surebet.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT team1, team2, score, prediction, result
        FROM yesterday_scores 
        WHERE date = ?
        ORDER BY created_at DESC
    ''', (yesterday,))
    scores = [{
        'team1': row[0], 'team2': row[1], 'score': row[2],
        'prediction': row[3], 'result': row[4]
    } for row in cursor.fetchall()]
    conn.close()
    return jsonify(scores)

@app.route('/admin/api/add-prediction', methods=['POST'])
@login_required
def add_prediction():
    data = request.get_json()
    conn = sqlite3.connect('surebet.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO predictions (date, team1, team2, prediction, odds, confidence, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('date', datetime.now().strftime('%Y-%m-%d')),
        data['team1'],
        data['team2'],
        data['prediction'],
        data.get('odds', ''),
        data.get('confidence', 80),
        datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/admin/api/add-score', methods=['POST'])
@login_required
def add_score():
    data = request.get_json()
    conn = sqlite3.connect('surebet.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO yesterday_scores (date, team1, team2, score, prediction, result, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('date', (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')),
        data['team1'],
        data['team2'],
        data['score'],
        data.get('prediction', ''),
        data.get('result', ''),
        datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/admin/api/analytics')
@login_required
def get_analytics():
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

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
