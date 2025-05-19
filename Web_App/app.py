from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os

app = Flask(__name__)
app.secret_key = 'your-secret-key'

def init_db():
    with sqlite3.connect('luxen.db') as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                result TEXT
            )
        ''')
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        with sqlite3.connect('luxen.db') as conn:
            try:
                conn.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, password))
                return redirect('/login')
            except:
                return "User already exists."
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect('luxen.db') as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect('/dashboard')
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    if request.method == 'POST':
        file = request.files['scan']
        if file:
            filename = file.filename
            path = os.path.join('static', filename)
            file.save(path)
            with sqlite3.connect('luxen.db') as conn:
                conn.execute('INSERT INTO scans (user_id, filename, result) VALUES (?, ?, ?)',
                             (session['user_id'], filename, "Pending Analysis"))
    with sqlite3.connect('luxen.db') as conn:
        scans = conn.execute('SELECT * FROM scans WHERE user_id = ?', (session['user_id'],)).fetchall()
    return render_template('dashboard.html', scans=scans)

@app.route('/delete_scan', methods=['POST'])
def delete_scan():
    if 'user_id' not in session:
        return redirect('/login')
    scan_id = request.form['scan_id']
    with sqlite3.connect('luxen.db') as conn:
        conn.execute('DELETE FROM scans WHERE id=? AND user_id=?', (scan_id, session['user_id']))
    return redirect('/dashboard')

@app.route('/report/<int:scan_id>')
def report(scan_id):
    if 'user_id' not in session:
        return redirect('/login')
    with sqlite3.connect('luxen.db') as conn:
        scan = conn.execute('SELECT * FROM scans WHERE id=? AND user_id=?', (scan_id, session['user_id'])).fetchone()
    return render_template('report.html', scan=scan)

if __name__ == '__main__':
    app.run(debug=True)
