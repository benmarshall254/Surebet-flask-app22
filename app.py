from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from datetime import datetime, timedelta
import sqlite3
import os
import hashlib
import json
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Database initialization
def init_db():
    conn = sqlite3.connect('surebet.db')
    cursor = conn.cursor()
    
    # Analytics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    
    # Admin users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    
    # Predictions table
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
    
    # Yesterday scores table
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
    
    # Create default admin user if not exists
    cursor.execute('SELECT COUNT(*) FROM admin_users')
    if cursor.fetchone()[0] == 0:
        password_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        cursor.execute('''
            INSERT INTO admin_users (username, password_hash, created_at)
            VALUES (?, ?, ?)
        ''', ('admin', password_hash, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Main Routes
@app.route('/')
def index():
    return render_template('index.html')

# Basic login route (from first code)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Simple check, replace with your logic
        if request.form['username'] == 'admin' and request.form['password'] == 'admin123':
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials"
    return render_template('login.html')

# Basic dashboard route (from first code)
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

# Analytics endpoint
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

# Admin authentication
@app.route('/admin/login', methods=['POST'])
def admin_login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username and password:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect('surebet.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id FROM admin_users 
            WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))
        
        if cursor.fetchone():
            session['admin_logged_in'] = True
            session['admin_username'] = username
            conn.close()
            return redirect(url_for('admin_dashboard'))
        
        conn.close()
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

# API endpoints for predictions and scores
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
    
    predictions = []
    for row in cursor.fetchall():
        predictions.append({
            'team1': row[0],
            'team2': row[1],
            'prediction': row[2],
            'odds': row[3],
            'confidence': row[4],
            'status': row[5]
        })
    
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
    
    scores = []
    for row in cursor.fetchall():
        scores.append({
            'team1': row[0],
            'team2': row[1],
            'score': row[2],
            'prediction': row[3],
            'result': row[4]
        })
    
    conn.close()
    return jsonify(scores)

# Admin API endpoints
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
    
    # Get total visits
    cursor.execute('SELECT COUNT(*) FROM analytics')
    total_visits = cursor.fetchone()[0]
    
    # Get today's visits
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('SELECT COUNT(*) FROM analytics WHERE DATE(timestamp) = ?', (today,))
    today_visits = cursor.fetchone()[0]
    
    # Get page visits
    cursor.execute('''
        SELECT page, COUNT(*) as count 
        FROM analytics 
        GROUP BY page 
        ORDER BY count DESC
    ''')
    page_stats = cursor.fetchall()
    
    # Get recent visits
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

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)
