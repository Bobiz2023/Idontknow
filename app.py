from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'database.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fullname TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL)''')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    fullname = request.form['fullname']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    
    if password != confirm_password:
        flash('كلمة المرور وتأكيد كلمة المرور غير متطابقتين')
        return redirect(url_for('index'))
    
    hashed_password = generate_password_hash(password, method='sha256')
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)",
                        (fullname, email, hashed_password))
            conn.commit()
        flash('تم التسجيل بنجاح! يمكنك الآن تسجيل الدخول')
    except sqlite3.IntegrityError:
        flash('البريد الإلكتروني مسجل بالفعل')
    
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['fullname'] = user[1]
            flash('تم تسجيل الدخول بنجاح')
            return redirect(url_for('index'))
        else:
            flash('البريد الإلكتروني أو كلمة المرور غير صحيحة')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
