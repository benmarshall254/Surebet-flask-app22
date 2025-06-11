from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Rate limiter configuration (fixed)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Sample admin credentials
admin_username = 'admin'
admin_password = 'password'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == admin_username and password == admin_password:
            session['logged_in'] = True
            return redirect(url_for('admin_dashboard'))  # Correct reference
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/admin-dashboard.html')
@login_required
def admin_dashboard():  # Corrected function name here
    return render_template('admin-dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
