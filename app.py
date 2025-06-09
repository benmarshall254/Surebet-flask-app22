from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
import os
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configuration
class Config:
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
    COUNTER_FILE = 'counter.txt'
    ANALYTICS_FILE = 'analytics.json'
    SESSION_TIMEOUT = timedelta(hours=2)
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_ATTEMPTS_FILE = 'login_attempts.json'

# Initialize files
def initialize_files():
    """Initialize required data files if they don't exist"""
    if not os.path.exists(Config.COUNTER_FILE):
        with open(Config.COUNTER_FILE, 'w') as f:
            f.write('0')
    
    if not os.path.exists(Config.ANALYTICS_FILE):
        analytics_data = {
            'daily_visits': {},
            'total_visits': 0,
            'unique_visitors': {},
            'page_views': {},
            'referrers': {},
            'user_agents': {},
            'created_at': datetime.now().isoformat()
        }
        with open(Config.ANALYTICS_FILE, 'w') as f:
            json.dump(analytics_data, f, indent=2)
    
    if not os.path.exists(Config.LOGIN_ATTEMPTS_FILE):
        with open(Config.LOGIN_ATTEMPTS_FILE, 'w') as f:
            json.dump({}, f)

initialize_files()

# Security decorators
def login_required(f):
    """Decorator to require login for admin routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'login_time' in session:
            login_time = datetime.fromisoformat(session['login_time'])
            if datetime.now() - login_time > Config.SESSION_TIMEOUT:
                session.clear()
                flash('Session expired. Please log in again.', 'info')
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_login(ip_address):
    """Check if IP address has exceeded login attempts"""
    try:
        with open(Config.LOGIN_ATTEMPTS_FILE, 'r') as f:
            attempts = json.load(f)
        
        if ip_address in attempts:
            if attempts[ip_address]['count'] >= Config.MAX_LOGIN_ATTEMPTS:
                last_attempt = datetime.fromisoformat(attempts[ip_address]['last_attempt'])
                if datetime.now() - last_attempt < timedelta(minutes=30):
                    return False
                else:
                    # Reset attempts after 30 minutes
                    del attempts[ip_address]
                    with open(Config.LOGIN_ATTEMPTS_FILE, 'w') as f:
                        json.dump(attempts, f)
        
        return True
    except Exception as e:
        app.logger.error(f"Error checking login attempts: {e}")
        return True

def record_login_attempt(ip_address, success=False):
    """Record login attempt"""
    try:
        with open(Config.LOGIN_ATTEMPTS_FILE, 'r') as f:
            attempts = json.load(f)
        
        if success:
            # Clear attempts on successful login
            if ip_address in attempts:
                del attempts[ip_address]
        else:
            # Record failed attempt
            if ip_address not in attempts:
                attempts[ip_address] = {'count': 0, 'last_attempt': None}
            
            attempts[ip_address]['count'] += 1
            attempts[ip_address]['last_attempt'] = datetime.now().isoformat()
        
        with open(Config.LOGIN_ATTEMPTS_FILE, 'w') as f:
            json.dump(attempts, f)
    except Exception as e:
        app.logger.error(f"Error recording login attempt: {e}")

# Analytics functions
def get_visitor_count():
    """Get current visitor count"""
    try:
        with open(Config.COUNTER_FILE, 'r') as f:
            return int(f.read().strip())
    except (ValueError, FileNotFoundError):
        return 0

def increment_visitor_count():
    """Increment visitor count and update analytics"""
    try:
        count = get_visitor_count() + 1
        with open(Config.COUNTER_FILE, 'w') as f:
            f.write(str(count))
        
        update_analytics()
        return count
    except Exception as e:
        app.logger.error(f"Error incrementing visitor count: {e}")
        return get_visitor_count()

def update_analytics():
    """Update detailed analytics data"""
    try:
        with open(Config.ANALYTICS_FILE, 'r') as f:
            analytics = json.load(f)
        
        today = datetime.now().strftime('%Y-%m-%d')
        user_ip = request.environ.get('REMOTE_ADDR', 'unknown')
        user_agent = request.headers.get('User-Agent', 'unknown')
        referrer = request.headers.get('Referer', 'direct')
        page = request.endpoint or 'unknown'
        
        # Update daily visits
        if today not in analytics['daily_visits']:
            analytics['daily_visits'][today] = 0
        analytics['daily_visits'][today] += 1
        
        # Update total visits
        analytics['total_visits'] += 1
        
        # Track unique visitors (simplified - using IP)
        if user_ip not in analytics['unique_visitors']:
            analytics['unique_visitors'][user_ip] = {
                'first_visit': datetime.now().isoformat(),
                'visit_count': 0
            }
        analytics['unique_visitors'][user_ip]['visit_count'] += 1
        analytics['unique_visitors'][user_ip]['last_visit'] = datetime.now().isoformat()
        
        # Track page views
        if page not in analytics['page_views']:
            analytics['page_views'][page] = 0
        analytics['page_views'][page] += 1
        
        # Track referrers
        if referrer not in analytics['referrers']:
            analytics['referrers'][referrer] = 0
        analytics['referrers'][referrer] += 1
        
        # Track user agents (browsers)
        if user_agent not in analytics['user_agents']:
            analytics['user_agents'][user_agent] = 0
        analytics['user_agents'][user_agent] += 1
        
        analytics['last_updated'] = datetime.now().isoformat()
        
        with open(Config.ANALYTICS_FILE, 'w') as f:
            json.dump(analytics, f, indent=2)
            
    except Exception as e:
        app.logger.error(f"Error updating analytics: {e}")

def get_analytics_data():
    """Get analytics data for admin dashboard"""
    try:
        with open(Config.ANALYTICS_FILE, 'r') as f:
            analytics = json.load(f)
        
        # Calculate additional metrics
        unique_visitor_count = len(analytics['unique_visitors'])
        
        # Get last 7 days data
        last_7_days = {}
        for i in range(7):
            date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
            last_7_days[date] = analytics['daily_visits'].get(date, 0)
        
        # Top pages
        top_pages = sorted(analytics['page_views'].items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Top referrers (excluding direct visits)
        top_referrers = [(k, v) for k, v in analytics['referrers'].items() if k != 'direct']
        top_referrers = sorted(top_referrers, key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'total_visits': analytics['total_visits'],
            'unique_visitors': unique_visitor_count,
            'last_7_days': last_7_days,
            'top_pages': top_pages,
            'top_referrers': top_referrers,
            'last_updated': analytics.get('last_updated', 'Unknown')
        }
    except Exception as e:
        app.logger.error(f"Error getting analytics data: {e}")
        return None

# Request tracking
@app.before_request
def track_visits():
    """Track visitor data before each request"""
    # Skip tracking for admin routes and static files
    if request.endpoint in ['admin', 'login', 'logout', 'api_analytics'] or \
       request.path.startswith('/static/'):
        return
    
    try:
        increment_visitor_count()
        app.logger.info(f"Visit tracked: {request.endpoint} from {request.environ.get('REMOTE_ADDR')}")
    except Exception as e:
        app.logger.error(f"Error tracking visit: {e}")

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal server error: {error}")
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# Routes
@app.route('/')
def home():
    """Home page route"""
    try:
        visitor_count = get_visitor_count()
        return render_template('index.html', visitor_count=visitor_count)
    except Exception as e:
        app.logger.error(f"Error in home route: {e}")
        return render_template('index.html', visitor_count=0)

@app.route('/about')
def about():
    """About page route"""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Contact page route"""
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    """Privacy policy page"""
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    """Terms of service page"""
    return render_template('terms.html')

@app.route('/admin')
@login_required
def admin():
    """Admin dashboard"""
    try:
        visitor_count = get_visitor_count()
        analytics_data = get_analytics_data()
        
        return render_template('admin.html', 
                             count=visitor_count,
                             analytics=analytics_data)
    except Exception as e:
        app.logger.error(f"Error in admin route: {e}")
        flash('Error loading dashboard data.', 'error')
        return render_template('admin.html', count=0, analytics=None)

@app.route('/api/analytics')
@login_required
def api_analytics():
    """API endpoint for analytics data"""
    try:
        analytics_data = get_analytics_data()
        if analytics_data:
            return jsonify(analytics_data)
        else:
            return jsonify({'error': 'Unable to load analytics data'}), 500
    except Exception as e:
        app.logger.error(f"Error in analytics API: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication"""
    if session.get('logged_in'):
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            ip_address = request.environ.get('REMOTE_ADDR', 'unknown')
            
            # Check rate limiting
            if not rate_limit_login(ip_address):
                flash('Too many failed login attempts. Please try again in 30 minutes.', 'error')
                return render_template('login.html')
            
            # Validate credentials
            if username == Config.ADMIN_USERNAME and check_password_hash(Config.ADMIN_PASSWORD_HASH, password):
                session['logged_in'] = True
                session['username'] = username
                session['login_time'] = datetime.now().isoformat()
                
                record_login_attempt(ip_address, success=True)
                
                flash('Successfully logged in!', 'success')
                app.logger.info(f"Successful login from {ip_address}")
                
                next_page = request.args.get('next')
                return redirect(next_page or url_for('admin'))
            else:
                record_login_attempt(ip_address, success=False)
                flash('Invalid username or password.', 'error')
                app.logger.warning(f"Failed login attempt from {ip_address}")
                
        except Exception as e:
            app.logger.error(f"Error in login route: {e}")
            flash('An error occurred during login.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    if session.get('logged_in'):
        app.logger.info(f"User {session.get('username')} logged out")
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Basic health checks
        visitor_count = get_visitor_count()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'visitor_count': visitor_count,
            'version': '2.0.0'
        })
    except Exception as e:
        app.logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

# Context processor for global template variables
@app.context_processor
def inject_global_vars():
    """Inject global variables into all templates"""
    return {
        'current_year': datetime.now().year,
        'app_name': 'Professional Flask App',
        'app_version': '2.0.0'
    }

# Custom template filters
@app.template_filter('datetime')
def datetime_filter(value):
    """Format datetime for templates"""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return value

@app.template_filter('number_format')
def number_format_filter(value):
    """Format numbers with commas"""
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value

if __name__ == '__main__':
    # Development server configuration
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    app.logger.info(f"Starting Flask application on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
