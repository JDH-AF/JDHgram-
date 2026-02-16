from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_key_123')

# Указываем серверу, где именно лежать файлу базы данных
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Адрес базы данных тоже берем из настроек сервера
uri = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Модели Базы Данных ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
    	self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    def check_password(self, password):
    	return check_password_hash(self.password_hash, password)
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Связи для удобного доступа
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Маршруты (Routes) ---

@app.route('/')
@login_required
def index():
    # Показываем всех пользователей, кроме себя
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('index.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(email=email).first():
            flash('Email уже занят')
            return redirect(url_for('register'))
        
        user = User(email=email, username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Неверный email или пароль')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    recipient = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        body = request.form['message']
        if body:
            msg = Message(sender_id=current_user.id, recipient_id=user_id, body=body)
            db.session.add(msg)
            db.session.commit()
        return redirect(url_for('chat', user_id=user_id))

    # Получаем переписку: (Я отправил ЕМУ) ИЛИ (ОН отправил МНЕ)
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp).all()

    return render_template('chat.html', recipient=recipient, messages=messages)

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Создаем БД при запуске
    app.run(debug=True)
    