# LoginSystem.py
from flask import Flask, request, redirect, url_for, render_template, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
import os
from functools import wraps
import re
import secrets
import hashlib

# ---------- Configuración ----------
SECRET_KEY = os.environ.get('APP_SECRET', 'this-should-be-changed-in-prod')
RESET_SALT = 'password-reset-salt'
DB_PATH = 'users.db'
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 300
TOKEN_EXPIRATION = 3600

app = Flask(__name__)
app.secret_key = SECRET_KEY
serializer = URLSafeTimedSerializer(app.secret_key)

COMPROMISED_PASSWORDS = {
    "123456", "password", "qwerty", "admin", "111111",
    "abc123", "letmein", "123456789", "iloveyou"
}


# ---------- Validaciones ----------
EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

def is_valid_email(email: str) -> bool:
    return EMAIL_REGEX.match(email) is not None


def is_valid_name(name: str) -> bool:
    # allow-list básica: letras, espacios y acentos
    return re.match(r"^[A-Za-zÁÉÍÓÚáéíóúÑñ ]+$", name) is not None

# ---------- Helpers de base de datos ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Tabla de usuarios
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            nombre_completo TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until TEXT DEFAULT NULL,
            estado TEXT NOT NULL DEFAULT 'PENDING'
        )
    """)

    # Tabla de tokens de verificación de email
    cur.execute("""
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_ip TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Tabla de auditoría
    cur.execute("""
        CREATE TABLE IF NOT EXISTS verification_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            verified_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

# Inicializar DB (crea tablas si no existen)
init_db()

# ---------- Funciones auxiliares ----------
def find_user_by_username(username):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    conn.close()
    return user

def find_user_by_email(email):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cur.fetchone()
    conn.close()
    return user

def find_user_by_id(uid):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))
    user = cur.fetchone()
    conn.close()
    return user

def update_user_field(uid, field, value):
    # field viene de código controlado (usar con precaución)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f'UPDATE users SET {field} = ? WHERE id = ?', (value, uid))
    conn.commit()
    conn.close()


# ---------- Envío de email simulado ----------
def send_email_verification(email, link):
    """
    Simula el envío de un email. En producción reemplazar por integración SMTP/servicio.
    """
    print("\n=== EMAIL DE VERIFICACIÓN (simulado) ===")
    print(f"Para: {email}")
    print(f"Enlace: {link}")
    print("========================================\n")

# ---------- Autenticación ----------
def login_user(user):
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']

def logout_user():
    session.clear()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Debes iniciar sesión para acceder a esa página.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ---------- Rutas ----------
@app.route('/')
def index():
    return render_template('base.html', title='Página principal')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        nombre_completo = request.form.get("nombre_completo", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Campos obligatorios
        if not username or not email or not nombre_completo or not password or not confirm_password:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(url_for("register"))
        
        # Validación de contraseña NO contenga nombre/apellido
        name_parts = nombre_completo.lower().split()
        for part in name_parts:
            part = part.strip()
            if len(part) >= 3 and part in password.lower():
                flash("La contraseña no puede contener tu nombre o apellido.", "error")
                return redirect(url_for("register"))

        # Validación contraseñas comprometidas
        if password.lower() in COMPROMISED_PASSWORDS:
            flash("Esa contraseña está comprometida, elegí otra más segura.", "error")
            return redirect(url_for("register"))

        # Confirmación de contraseña (importante en server-side)
        if password != confirm_password:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for("register"))

        # Validaciones allow-list (mensajes específicos para ayudar)
        if not is_valid_email(email):
            flash("El email no tiene un formato válido.", "error")
            return redirect(url_for("register"))

        if not is_valid_name(nombre_completo):
            flash("El nombre solo puede contener letras y espacios.", "error")
            return redirect(url_for("register"))

        
        if find_user_by_username(username):
            flash("Ese nombre de usuario ya existe.", "error")
            return redirect(url_for("register"))

        # Validar email repetido
        if find_user_by_email(email):
            flash("Ese email ya está registrado.", "error")
            return redirect(url_for("register"))

        # =============================
        # Guardar usuario en estado PENDING
        # =============================
        pwd_hash = generate_password_hash(password)
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO users (username, email, nombre_completo, password_hash, estado, created_at)
            VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
        """, (username, email, nombre_completo, pwd_hash, datetime.utcnow().isoformat()))
        conn.commit()
        user_id = cur.lastrowid

        # =============================
        # Generar token seguro y guardar sólo HASH
        # =============================
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        ip = request.remote_addr or "0.0.0.0"

        cur.execute("""
            INSERT INTO email_verification_tokens
                (user_id, token_hash, expires_at, created_ip, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, token_hash, expires_at, ip, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        # Simular envío de email (en producción se envía realmente)
        verify_url = url_for("verify_email", token=raw_token, _external=True)
        send_email_verification(email, verify_url)

        flash("Si existe una cuenta vinculada, se ha enviado un correo de verificación.", "ok")
        return redirect(url_for("login"))

    return render_template("register.html", title="Registrarse")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = find_user_by_username(username)
        if not user:
            flash('Credenciales inválidas.', 'error')
            return redirect(url_for('login'))

        # Verificar que usuario esté ENROLLED (email verificado)
        if user['estado'] != 'ENROLLED':
            flash('Debes verificar tu correo antes de iniciar sesión.', 'error')
            return redirect(url_for('login'))

        # Check lockout
        if user['lockout_until']:
            try:
                lockout_until = datetime.fromisoformat(user['lockout_until'])
                if datetime.utcnow() < lockout_until:
                    remaining = (lockout_until - datetime.utcnow()).seconds
                    flash(f'Cuenta bloqueada. Intenta de nuevo en {remaining} segundos.', 'error')
                    return redirect(url_for('login'))
            except Exception:
                pass

        if check_password_hash(user['password_hash'], password):
            update_user_field(user['id'], 'failed_attempts', 0)
            update_user_field(user['id'], 'lockout_until', None)
            login_user(user)
            flash('Has iniciado sesión correctamente.', 'ok')
            return redirect(url_for('profile'))
        else:
            new_fail = (user['failed_attempts'] or 0) + 1
            update_user_field(user['id'], 'failed_attempts', new_fail)
            if new_fail >= LOCKOUT_THRESHOLD:
                until = datetime.utcnow() + timedelta(seconds=LOCKOUT_DURATION)
                update_user_field(user['id'], 'lockout_until', until.isoformat())
                flash('Has excedido el número de intentos. Cuenta bloqueada temporalmente.', 'error')
            else:
                flash('Usuario o contraseña incorrectos.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html', title='Iniciar sesión')

@app.route('/logout')
def logout():
    logout_user()
    flash('Sesión cerrada.', 'ok')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    user = find_user_by_id(session['user_id'])
    return render_template('profile.html', title='Perfil', user=user)

@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current','')
        newpwd = request.form.get('new','')
        user = find_user_by_id(session['user_id'])
        if not check_password_hash(user['password_hash'], current):
            flash('Contraseña actual incorrecta.', 'error')
            return redirect(url_for('change_password'))
        update_user_field(user['id'], 'password_hash', generate_password_hash(newpwd))
        flash('Contraseña actualizada.', 'ok')
        return redirect(url_for('profile'))
    return render_template('change_password.html', title='Cambiar contraseña')

@app.route('/reset-password-request', methods=['GET','POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        user = find_user_by_email(email)
        if user:
            token = serializer.dumps({'id': user['id'], 'email': user['email']}, salt=RESET_SALT)
            reset_url = url_for('reset_password', token=token, _external=True)
            print('--- PASSWORD RESET LINK (simulado) ---')
            print(reset_url)
            print('--------------------------------------')
        flash('Si el email está registrado, se ha enviado un enlace de recuperación (simulado).', 'ok')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Recuperar contraseña')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    try:
        data = serializer.loads(token, salt=RESET_SALT, max_age=TOKEN_EXPIRATION)
    except Exception:
        flash('Token inválido o expirado.', 'error')
        return redirect(url_for('login'))
    user = find_user_by_id(data['id'])
    if not user or user['email'] != data['email']:
        flash('Token inválido.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        newpwd = request.form.get('new','')
        update_user_field(user['id'], 'password_hash', generate_password_hash(newpwd))
        flash('Contraseña actualizada. Inicia sesión.', 'ok')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='Restablecer contraseña')

@app.route("/verify_email/<token>")
def verify_email(token):
    print("\n================ VERIFICACIÓN DE EMAIL ================")
    print("Token recibido en la URL:", token)

    # HASH del token recibido
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    print("Hash generado del token recibido:", token_hash)

    conn = get_db()
    cur = conn.cursor()

    # Obtener token en BD
    cur.execute("""
        SELECT id, user_id, token_hash, expires_at
        FROM email_verification_tokens
        WHERE token_hash = ?
    """, (token_hash,))
    
    row = cur.fetchone()
    print("Fila encontrada en la BD:", row)

    # --------------------------------------------------
    # 1. Token no existe → probablemente hash no coincide
    # --------------------------------------------------
    if not row:
        print("❌ ERROR: Token NO coincide con ninguno guardado en la BD")
        
        # Mostrar lo que hay en la BD para comparar
        cur.execute("SELECT id, user_id, token_hash FROM email_verification_tokens")
        print("Tokens guardados actualmente:", cur.fetchall())

        conn.close()
        flash("El enlace no es válido o expiró.", "error")
        return redirect(url_for("register"))

    token_id, user_id, db_hash, expires_at = row

    print("✔ Token encontrado, verificando expiración...")
    print("Expira en:", expires_at)

    # --------------------------------------------------
    # 2. Token expirado
    # --------------------------------------------------
    try:
        exp_dt = datetime.fromisoformat(expires_at)
    except Exception as e:
        print("❌ ERROR al parsear fecha de expiración:", e)
        conn.close()
        flash("El enlace no es válido.", "error")
        return redirect(url_for("register"))

    if datetime.utcnow() > exp_dt:
        print("❌ ERROR: Token expirado a las", expires_at)
        conn.close()
        flash("El enlace expiró. Podés solicitar uno nuevo.", "error")
        return redirect(url_for("resend_verification"))

    print("✔ Token válido, verificando usuario...")

    # --------------------------------------------------
    # 3. Verificar usuario
    # --------------------------------------------------
    cur.execute("SELECT id, email, estado FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    print("Usuario encontrado:", user)

    if not user:
        print("❌ ERROR: No existe el usuario asociado al token")
        conn.close()
        flash("Error interno. Contactá soporte.", "error")
        return redirect(url_for("register"))

    # --------------------------------------------------
    # 4. Marcar usuario como verificado
    # --------------------------------------------------
    print("✔ Actualizando estado del usuario a ENROLLED...")
    cur.execute("UPDATE users SET estado='ENROLLED' WHERE id=?", (user_id,))

    print("✔ Registrando auditoría...")
    cur.execute("""
        INSERT INTO verification_audit (user_id, ip, verified_at)
        VALUES (?, ?, ?)
    """, (user_id, request.remote_addr, datetime.utcnow().isoformat()))

    print("✔ Eliminando token utilizado...")
    cur.execute("DELETE FROM email_verification_tokens WHERE id=?", (token_id,))

    conn.commit()
    conn.close()

    print("🎉 VERIFICACIÓN EXITOSA — Renderizando email_verified.html")
    print("===========================================================\n")

    return render_template("email_verified.html")


@app.route("/resend_verification", methods=["GET", "POST"])
def resend_verification():
    import os
    print("🟦 TEMPLATE FOLDER REAL:", app.template_folder)
    print("🟩 ARCHIVOS EN TEMPLATE FOLDER:", os.listdir(app.template_folder))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        generic_msg = "Si existe una cuenta vinculada, enviamos un nuevo correo."

        if not email:
            flash(generic_msg, "ok")
            return redirect(url_for("resend_verification"))

        user = find_user_by_email(email)

        # Si no existe o ya está verificado → mismo mensaje genérico
        if not user or user["estado"] == "ENROLLED":
            flash(generic_msg, "ok")
            return redirect(url_for("resend_verification"))

        # Crear nuevo token
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        ip = request.remote_addr or "0.0.0.0"

        conn = get_db()
        cur = conn.cursor()

        # eliminar tokens previos, si existen
        cur.execute("DELETE FROM email_verification_tokens WHERE user_id=?", (user["id"],))

        cur.execute("""
            INSERT INTO email_verification_tokens
                (user_id, token_hash, expires_at, created_ip, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user["id"], token_hash, expires_at, ip, datetime.utcnow().isoformat()))

        conn.commit()
        conn.close()

        # Enviar email (simulado)
        verification_link = url_for("verify_email", token=raw_token, _external=True)
        send_email_verification(email, verification_link)

        flash(generic_msg, "ok")
        return redirect(url_for("login"))

    return render_template("resend_verification.html")

if __name__ == "__main__":
    import socket, os

    def find_free_port(default=5000, max_tries=10):
        port = default
        for _ in range(max_tries):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("127.0.0.1", port))
                    return port
                except OSError:
                    port += 1
        raise RuntimeError("No se encontró un puerto libre en el rango.")

    port = find_free_port()

    if not os.environ.get("FLASK_RUN_FROM_CLI") and not os.environ.get("WERKZEUG_RUN_MAIN"):
        print(f"🚀 Servidor corriendo en http://127.0.0.1:{port}")

    app.run(host="127.0.0.1", port=port, debug=True)


#------------------------------------------------------------------------------------------------------------------------------------- 
#Crear entorno para correr: 
# conda create -n loginenv python=3.11 flask itsdangerous 
# conda activate loginenv 

# Para ver la base de datos: 
# sqlite3 users.db 
# .tables 
# SELECT * FROM users; 
# .exit 

