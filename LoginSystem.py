from flask import Flask, request, redirect, url_for, render_template, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
import os
from functools import wraps

'''
Flask: la clase principal para crear la aplicación web.

request: contiene datos de la petición HTTP (formulario enviado, query params, etc.).

redirect: sirve para devolver al navegador una redirección a otra URL.

url_for: genera la URL de una función/ruta por su nombre (útil para no escribir rutas a mano).

render_template: carga un archivo HTML (template) y lo rellena con datos.

session: un diccionario donde guardamos datos temporales del usuario (por ejemplo user_id) persistente entre requests (almacenado en cookies firmadas).

flash: permite enviar mensajes temporales (por ejemplo “Cuenta creada”) que el template puede mostrar.

sqlite3: módulo para usar la base de datos SQLite (archivo .db).

werkzeug.security.generate_password_hash / check_password_hash: funciones para hashear (guardar de forma segura) y verificar contraseñas.

itsdangerous.URLSafeTimedSerializer: genera y valida tokens seguros (usamos para "reset password").

datetime, timedelta: manejo de fechas y tiempos.

os: interactuar con variables de entorno y filesystem.

wraps (de functools): utilidad para crear decoradores (como login_required) sin perder metadatos de la función original.

'''

# ---------- Configuración ----------
SECRET_KEY = os.environ.get('APP_SECRET', 'this-should-be-changed-in-prod') 
# Clave secreta que Flask usa para firmar cookies, tokens y otros datos. Si alguien conoce esa clave, puede falsificar sesiones o cookies y suplantar usuarios.

RESET_SALT = 'password-reset-salt' #valor adicional (salt/namespace) que combinamos con la secret_key para generar tokens de recuperación con itsdangerous.
#me parece que en la practica SECRET_KEY y RESET_SALT se generan de manera aleotria, pero me parece que es un kilomo implementarlo porque hay que asegurrase de NO generar valores nuevos cada vez que arrancás la app (sino, se invalidán todas las sesiones y tokens anteriores).

DB_PATH = 'users.db'
LOCKOUT_THRESHOLD = 5         # intentos fallidos permitidos
LOCKOUT_DURATION = 300        # segundos (5 minutos)
TOKEN_EXPIRATION = 3600       # segundos (1 hora)

app = Flask(__name__)   #inicia la applicación Flask 
app.secret_key = SECRET_KEY
serializer = URLSafeTimedSerializer(app.secret_key)  #objeto que crea tokens firmados y con expiración (lo usamos para enviar enlaces de recuperación seguros).

# ---------- Helpers de base de datos ----------

def get_db():
    '''get_db() abre conexión a users.db y configura que las filas devueltas se puedan leer como diccionarios (row['username']) en vez de tuplas.'''
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    '''crea la tabla users si no existe'''

    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL, 
            failed_attempts INTEGER DEFAULT 0,
            lockout_until TEXT DEFAULT NULL
        )
    ''')
    conn.commit()
    conn.close()

    #la columna created_at no estoy segura si deberiamos guardarla, me suena que algo de esto dijo Kebo en la tutorial pero no me acuerdo. 

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
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f'UPDATE users SET {field} = ? WHERE id = ?', (value, uid))
    conn.commit()
    conn.close()

# ---------- Autenticación ----------

def login_user(user):
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']

def logout_user():
    session.clear()

def login_required(f):
    '''login_required es un decorador: lo ponés encima de una función de ruta (por ejemplo @login_required) y obliga a que el usuario esté logueado (tiene user_id en session). Si no lo está, lo redirige a la página de login con un mensaje flash'''

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
    '''Si la petición es GET: devuelve el formulario register.html.

        Si es POST (cuando el usuario envía el formulario):

            Lee username, email, password desde request.form.

            Valida que no estén vacíos.

            Verifica que el usuario o email no existan.

            Hashea la contraseña con generate_password_hash(password) (esto transforma la contraseña en una cadena segura, irreversiblemente).

            Inserta una fila nueva en la tabla users.

            Muestra un mensaje de éxito (flash) y redirige al login.
    '''
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not username or not email or not password:
            flash('Todos los campos son obligatorios.', 'error')
            return redirect(url_for('register'))
        if find_user_by_username(username) or find_user_by_email(email):
            flash('Nombre de usuario o correo ya registrado.', 'error')
            return redirect(url_for('register'))
        pwd_hash = generate_password_hash(password)
        conn = get_db()
        cur = conn.cursor()
        cur.execute('INSERT INTO users (username,email,password_hash,created_at) VALUES (?,?,?,?)',
                    (username, email, pwd_hash, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        flash('Cuenta creada correctamente. Inicia sesión.', 'ok')
        return redirect(url_for('login'))
    return render_template('register.html', title='Registrarse')



@app.route('/login', methods=['GET','POST'])
def login():
    '''GET: muestra el formulario login.html.

        POST: procesa el login:

            Busca el usuario por username. Si no existe, falla temprano (mensaje genérico para no revelar qué no existe).

            Verifica si la cuenta está bloqueada leyendo lockout_until. Si la fecha actual es anterior, muestra cuánto falta para desbloquear.

            check_password_hash(stored_hash, provided_password): compara el hash guardado con el hash de la contraseña ingresada. No desencripta nada — recalcula y compara.

            Si la contraseña es correcta: resetea failed_attempts, borra lockout_until, llama a login_user(user) (pone user_id en session) y redirige al perfil.

            Si es incorrecta: incrementa failed_attempts, y si supera el LOCKOUT_THRESHOLD, fija lockout_until a ahora + LOCKOUT_DURATION.

        Este bloque implementa medidas básicas de protección contra fuerza bruta.
    '''

    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = find_user_by_username(username)
        if not user:
            flash('Usuario o contraseña incorrectos.', 'error')
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
            new_fail = user['failed_attempts'] + 1
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
    '''Limpia session y redirige a la página principal.'''

    logout_user()
    flash('Sesión cerrada.', 'ok')
    return redirect(url_for('index'))



@app.route('/profile')
@login_required
def profile():
    '''Está protegido con @login_required, por lo que solo se puede acceder estando logueado.
        Busca el usuario por user_id almacenado en session y muestra profile.html pasando user como contexto (para que el HTML muestre user.username, user.email, etc.).    
'''

    user = find_user_by_id(session['user_id'])
    return render_template('profile.html', title='Perfil', user=user)



@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    '''GET: muestra formulario para ingresar la contraseña actual y la nueva.

        POST: comprueba la contraseña actual con check_password_hash; si coincide, guarda el hash de la nueva contraseña. Mensaje y redirección de éxito.
    '''

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
    '''GET: muestra formulario para ingresar el email.

        POST: si el email está en la DB, genera un token firmado con serializer.dumps(...) que incluye id y email.

            reset_url = url_for('reset_password', token=token, _external=True) genera el enlace completo (ej. http://127.0.0.1:5001/reset-password/<token>).

            Aquí se imprime el link en consola (simula enviar un email). En producción se enviaría por email real.

    Nota de seguridad: se muestra siempre el mismo mensaje al usuario (no revela si el email existe).
'''
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
    ''' serializer.loads(...) valida la firma del token y que no haya expirado (max_age).

        Verifica que el user y el email concuerden con la info del token.

        GET: muestra formulario donde ingresar la nueva contraseña.

        POST: guarda el hash de la nueva contraseña.
'''

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

'''
Crear entorno para correr: 

conda create -n loginenv python=3.11 flask itsdangerous
conda activate loginenv

'''



'''
Para ver la base de datos: 

sqlite3 users.db
.tables
SELECT * FROM users;
.exit

'''


'''Notas y recomendaciones de seguridad (importante para el TP)

No uses debug=True en producción. Expone el stacktrace y permite ejecutar código desde el navegador si activás el debugger.

Cambiá APP_SECRET por una string larga y aleatoria en producción (nunca lo dejes por defecto).

Usá HTTPS y cabeceras de seguridad (CSP, HSTS) en producción.

Marcar cookies de sesión con Secure, HttpOnly, y SameSite para mayor seguridad.

Para formularios, implementá protección CSRF (Flask-WTF la provee).

Considerá usar Flask-Login para manejar sesiones y Flask-Limiter para rate-limiting.

Validá la complejidad de passwords y usa un método robusto de hashing (PBKDF2/Scrypt/Argon2). werkzeug ya lo hace por vos si tu instalación lo soporta.'''

