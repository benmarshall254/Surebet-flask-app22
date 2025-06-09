from flask import Flask, render_template, request, redirect, url_for, session
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'surebetsecret123'

# Initialize visitor counter
counter_file = 'counter.txt'
if not os.path.exists(counter_file):
    with open(counter_file, 'w') as f:
        f.write('0')

def get_visitor_count():
    with open(counter_file, 'r') as f:
        return int(f.read())

def increment_visitor_count():
    count = get_visitor_count() + 1
    with open(counter_file, 'w') as f:
        f.write(str(count))

@app.before_request
def track_visits():
    if request.endpoint != 'admin':
        increment_visitor_count()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    count = get_visitor_count()
    return render_template('admin.html', count=count)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == 'admin' and request.form['password'] == 'admin123':
            session['logged_in'] = True
            return redirect(url_for('admin'))
        else:
            return 'Invalid Credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
