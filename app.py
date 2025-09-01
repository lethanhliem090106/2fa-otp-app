import os
import secrets
import sqlite3
import base64
import struct
import hmac
import hashlib
import time
import io
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

def get_db_conn():
    db_path = os.path.join(os.path.dirname(__file__), 'users.db')
    return sqlite3.connect(db_path)

def init_db():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password_hash TEXT, secret TEXT, hotp_counter INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

init_db()

def hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret.upper(), True)
    msg = struct.pack(">Q", counter)
    hash_value = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hash_value[-1] & 0xF
    binary = struct.unpack(">I", hash_value[offset:offset+4])[0] & 0x7FFFFFFF
    otp = binary % (10 ** digits)
    return f"{otp:0{digits}d}"

def totp(secret: str, digits: int = 6, period: int = 30) -> str:
    counter = int(time.time()) // period
    return hotp(secret, counter, digits)

def time_remaining(period: int = 30) -> int:
    return period - (int(time.time()) % period)

def generate_secret(length: int = 16) -> str:
    return base64.b32encode(secrets.token_bytes(length)).decode('utf-8').rstrip('=')

def generate_qr(secret: str, username: str) -> str:
    uri = f"otpauth://totp/{username}?secret={secret}&issuer=2FA-OTP-App"
    img = qrcode.make(uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()

@app.route("/", methods=["GET", "POST"])
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Vui lòng nhập đầy đủ thông tin!")
            return render_template("register.html")
        secret = generate_secret()
        conn = get_db_conn()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password_hash, secret) VALUES (?, ?, ?)",
                      (username, generate_password_hash(password), secret))
            conn.commit()
            session['username'] = username
            flash("Đăng ký thành công! Secret của bạn: " + secret)
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash("Username đã tồn tại!")
        finally:
            conn.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        otp = request.form.get("otp")
        if not username or not password or not otp:
            flash("Vui lòng nhập đầy đủ thông tin!")
            return render_template("login.html")
        conn = get_db_conn()
        c = conn.cursor()
        c.execute("SELECT password_hash, secret, hotp_counter FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[0], password):
            totp_code = totp(user[1])
            hotp_code = hotp(user[1], user[2])
            if otp == totp_code or otp == hotp_code:
                if otp == hotp_code:
                    conn = get_db_conn()
                    c = conn.cursor()
                    c.execute("UPDATE users SET hotp_counter = hotp_counter + 1 WHERE username=?", (username,))
                    conn.commit()
                    conn.close()
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                flash("OTP sai!")
        else:
            flash("Username hoặc password sai!")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT secret, hotp_counter FROM users WHERE username=?", (session['username'],))
    user = c.fetchone()
    conn.close()
    if not user:
        flash("Không tìm thấy user!")
        return redirect(url_for('logout'))
    secret = user[0]
    hotp_counter = user[1]
    qr_data = generate_qr(secret, session['username'])
    totp_code = totp(secret)
    hotp_code = hotp(secret, hotp_counter)
    remaining = time_remaining()
    return render_template("dashboard.html", qr_data=qr_data, totp_code=totp_code, hotp_code=hotp_code,
                           remaining=remaining, secret=secret, hotp_counter=hotp_counter)

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)