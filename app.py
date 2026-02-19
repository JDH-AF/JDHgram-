from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort, session
import logging
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key-change-in-production-2026'  # Не меняй!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///telegram_clone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = False  # Для dev; на production True + HTTPS

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

with app.app_context():
    db.create_all()
    logger.info("✅ База данных готова")

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
    logger.debug(f"Загрузка пользователя ID: {user_id}")
    return User.query.get(int(user_id))

def can_access_chat(current_user, other_id):
    if other_id == current_user.id:
        return False
    return User.query.get(other_id) is not None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    logger.debug(f"REGISTER: Метод {request.method}, данные формы: {request.form}")
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')

            if not all([email, username, password]):
                flash('Заполните все поля', 'danger')
                return redirect(url_for('register'))

            if User.query.filter_by(email=email).first():
                flash('Этот email уже зарегистрирован', 'danger')
                return redirect(url_for('register'))
            if User.query.filter_by(username=username).first():
                flash('Это имя пользователя уже занято', 'danger')
                return redirect(url_for('register'))

            new_user = User(
                email=email,
                username=username,
                password=generate_password_hash(password, method='pbkdf2:sha256')
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user, remember=True)
            session['user_id'] = new_user.id  # Дополнительно для стабильности
            flash(f'Добро пожаловать, {username}!', 'success')
            logger.info(f"✅ Новый пользователь {username} зарегистрирован и вошёл")
            return redirect(url_for('chat'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"❌ Ошибка регистрации: {e}")
            flash('Ошибка. Попробуйте снова.', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    logger.debug(f"LOGIN: Метод {request.method}, данные формы: {request.form}")
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            session['user_id'] = user.id
            flash('Вы успешно вошли!', 'success')
            logger.info(f"✅ Пользователь {user.username} вошёл")
            return redirect(url_for('chat'))
        flash('Неверный email или пароль', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    logger.debug(f"CHAT: Пользователь {current_user.username} зашёл в чат")
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('chat.html', users=users)

# Остальные роуты и SocketIO без изменений (добавь из предыдущей версии)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
