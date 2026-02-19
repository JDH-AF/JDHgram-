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
    'pool_size': 20,
    'max_overflow': 30,
    'pool_timeout': 60,
    'pool_recycle': 1800,
    'pool_pre_ping': True
}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# WAL + создание таблиц (единственное место с контекстом)
with app.app_context():
    with db.engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
    logger.info("✅ WAL включён")
    db.create_all()
    logger.info("✅ База данных готова")

# ====================== MODELS ======================
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

# Retry только для критических операций
def with_db_retry(max_retries=3):
    def decorator(func):
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except OperationalError as e:
                    db.session.rollback()
                    logger.warning(f"DB retry {attempt+1}: {e}")
                    if attempt < max_retries - 1:
                        time.sleep(1.5 ** attempt)
                    else:
                        raise
        return wrapper
    return decorator

# ====================== ROUTES ======================
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@with_db_retry()
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        if not all([email, username, password]):
            flash('Заполните все поля', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email уже занят', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Имя пользователя занято', 'danger')
            return redirect(url_for('register'))

        new_user = User(
            email=email,
            username=username,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user, remember=True)
        flash(f'Добро пожаловать, {username}!', 'success')
        logger.info(f"✅ Зарегистрирован: {username}")
        return redirect(url_for('chat'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@with_db_retry()
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('Вы успешно вошли!', 'success')
            logger.info(f"✅ Вошёл: {user.username}")
            return redirect(url_for('chat'))
        flash('Неверный email или пароль', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('chat.html', users=users)

@app.route('/api/messages/<int:recipient_id>')
@login_required
def api_messages(recipient_id):
    if not can_access_chat(current_user, recipient_id):
        abort(403)
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == recipient_id)) |
        ((Message.sender_id == recipient_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    return jsonify([{
        'id': m.id,
        'sender_id': m.sender_id,
        'content': m.content,
        'timestamp': m.timestamp.strftime('%H:%M')
    } for m in messages])

# ====================== SOCKETIO ======================
@socketio.on('join')
def on_join(data):
    with app.app_context():
        room = data['room']
        try:
            uid1, uid2 = map(int, room.split('_'))
            if current_user.id not in (uid1, uid2):
                return
        except:
            return
        join_room(room)

@socketio.on('leave')
def on_leave(data):
    with app.app_context():
        leave_room(data['room'])

@socketio.on('message')
def handle_message(data):
    with app.app_context():
        try:
            recipient_id = int(data['recipient_id'])
            content = str(data.get('content', ''))[:2000]
        except:
            return
        if not can_access_chat(current_user, recipient_id):
            return

        room = '_'.join(sorted([str(current_user.id), str(recipient_id)]))

        msg = Message(sender_id=current_user.id, recipient_id=recipient_id, content=content)
        db.session.add(msg)
        db.session.commit()

        emit('new_message', {
            'sender_id': current_user.id,
            'username': current_user.username,
            'content': content,
            'timestamp': msg.timestamp.strftime('%H:%M')
        }, room=room)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
