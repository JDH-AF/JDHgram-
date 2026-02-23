# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Поменяй на свой случайный набор букв

# Настройка базы данных SQLite
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- МОДЕЛИ БАЗЫ ДАННЫХ ---

association_table = db.Table('user_chat',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('chat_id', db.Integer, db.ForeignKey('chat.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    chats = db.relationship('Chat', secondary=association_table, backref='users')

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    messages = db.relationship('Message', backref='chat', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Создаем базу данных
with app.app_context():
    db.create_all()

# --- МАРШРУТЫ (ROUTES) ---

@app.route('/')
@login_required
def index():
    # Список чатов текущего пользователя
    chats = current_user.chats
    return render_template('index.html', chats=chats)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        
        if User.query.filter_by(username=username).first():
            flash('Это имя пользователя уже занято.')
            return redirect(url_for('register'))
            
        user = User(username=username)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        
        if user:
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/create_chat', methods=['GET', 'POST'])
@login_required
def create_chat():
    if request.method == 'POST':
        key = request.form['key']
        if not key:
            flash('Ключ не может быть пустым.')
            return redirect(url_for('create_chat'))
        
        existing_chat = Chat.query.filter_by(key=key).first()
        
        if existing_chat:
            if current_user in existing_chat.users:
                flash('Вы уже в этом чате.')
                return redirect(url_for('index'))
            if len(existing_chat.users) >= 2:
                flash('Этот чат уже заполнен (максимум 2 пользователя).')
                return redirect(url_for('create_chat'))
            existing_chat.users.append(current_user)
            db.session.commit()
            flash('Вы присоединились к чату!')
        else:
            new_chat = Chat(key=key)
            new_chat.users.append(current_user)
            db.session.add(new_chat)
            db.session.commit()
            flash('Новый чат создан! Поделитесь ключом с собеседником.')
        
        return redirect(url_for('index'))
    
    return render_template('create_chat.html')

@app.route('/chat/<int:chat_id>', methods=['GET', 'POST'])
@login_required
def chat(chat_id):
    chat_room = Chat.query.get_or_404(chat_id)
    
    if current_user not in chat_room.users:
        flash('Вы не участник этого чата.')
        return redirect(url_for('index'))
    
    # ЛОГИКА ОТПРАВКИ
    if request.method == 'POST':
        message_body = request.form.get('message')
        if message_body:
            if len(chat_room.users) < 2:
                flash('Нельзя отправлять сообщения, пока не присоединится второй пользователь.')
                return redirect(url_for('chat', chat_id=chat_id))
            new_msg = Message(
                sender_id=current_user.id, 
                chat_id=chat_id, 
                body=message_body
            )
            db.session.add(new_msg)
            db.session.commit()
            return redirect(url_for('chat', chat_id=chat_id))

    # ВЫБОРКА СООБЩЕНИЙ
    messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.timestamp).all()
    
    return render_template('chat.html', chat_room=chat_room, messages=messages)

if __name__ == '__main__':
    app.run(debug=True)
