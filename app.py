from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort, session
import logging
import time
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key-change-in-production-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///telegram_clone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 5,          # Базовый пул
    'max_overflow': 10,      # Доп. connections
    'pool_timeout': 30,      # Таймаут ожидания
    'pool_recycle': 300,     # Recycle каждые 5 мин
    'pool_pre_ping': True    # Проверка connections
}
app.config['SESSION_COOKIE_SECURE'] = False  # Для dev

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# WAL mode + create_all
with app.app_context():
    with db.engine.connect() as connection:
        connection.execute(text("PRAGMA journal_mode=WAL"))
    logger.info("✅ WAL mode включён")
    db.create_all()
    logger.info("✅ База готова")

# Models (без изменений)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def can_access_chat(current_user, other_id):
    if other_id == current_user.id:
        return False
    return User.query.get(other_id) is not None

# Retry decorator для DB operations
def with_db_retry(func, max_retries=3):
    def wrapper(*args, **kwargs):
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except OperationalError as e:
                db.session.rollback()
                logger.warning(f"DB error (attempt {attempt+1}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
                else:
                    raise
    return wrapper

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    logger.debug(f"REGISTER: {request.method}, form: {request.form}")
    if request.method == 'POST':
        @with_db_retry
        def do_register():
            email = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')

            if not all([email, username, password]):
                flash('Заполните все поля', 'danger')
                return redirect(url_for('register'))

            if User.query.filter_by(email=email).first():
                flash('Email занят', 'danger')
                return redirect(url_for('register'))
            if User.query.filter_by(username=username).first():
                flash('Username занят', 'danger')
                return redirect(url_for('register'))

            new_user = User(email=email, username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user, remember=True)
            session['user_id'] = new_user.id
            flash(f'Добро пожаловать, {username}!', 'success')
            logger.info(f"✅ Зарегистрирован: {username}")
            return redirect(url_for('chat'))

        try:
            return do_register()
        except Exception as e:
            logger.error(f"❌ Регистрация failed: {str(e)}", exc_info=True)
            flash('Ошибка. Попробуйте позже.', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')

# Login (добавил retry для query)
@app.route('/login', methods=['GET', 'POST'])
def login():
    logger.debug(f"LOGIN: {request.method}, form: {request.form}")
    if request.method == 'POST':
        @with_db_retry
        def do_login():
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password, password):
                login_user(user, remember=True)
                session['user_id'] = user.id
                flash('Вход успешен!', 'success')
                logger.info(f"✅ Вход: {user.username}")
                return redirect(url_for('chat'))
            flash('Неверные данные', 'danger')
            return None

        result = do_login()
        if result:
            return result
    return render_template('login.html')

# Остальные routes и SocketIO без изменений (добавь из предыдущей версии)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
