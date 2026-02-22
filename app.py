import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from cipher import encrypt_message, decrypt_message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'jdh_secret_777'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Связь многие-ко-многим: Пользователи <-> Комнаты
user_rooms = db.Table('user_rooms',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('room_id', db.Integer, db.ForeignKey('room.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    rooms = db.relationship('Room', secondary=user_rooms, backref=db.backref('members', lazy='dynamic'))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    messages = db.relationship('Message', backref='room', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/')
@login_required
def index():
    return render_template('index.html', rooms=current_user.rooms)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        room_code = request.form.get('room_code').strip()

        if User.query.filter_by(username=username).first():
            flash('Имя уже занято')
            return redirect(url_for('register'))

        user = User(username=username)
        user.set_password(password)
        if room_code:
            room = Room.query.filter_by(code=room_code).first()
            if not room:
                room = Room(code=room_code)
                db.session.add(room)
            user.rooms.append(room)
        
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверное имя или пароль')
    return render_template('login.html')

@app.route('/add_room', methods=['POST'])
@login_required
def add_room():
    code = request.form.get('room_code').strip()
    if code:
        room = Room.query.filter_by(code=code).first()
        if not room:
            room = Room(code=code)
            db.session.add(room)
        if room not in current_user.rooms:
            current_user.rooms.append(room)
            db.session.commit()
        return redirect(url_for('chat', room_id=room.id))
    return redirect(url_for('index'))

@app.route('/chat/<int:room_id>', methods=['GET', 'POST'])
@login_required
def chat(room_id):
    room = Room.query.get_or_404(room_id)
    if room not in current_user.rooms:
        return redirect(url_for('index'))

    if request.method == 'POST':
        body = request.form.get('message')
        if body:
            encrypted_body = encrypt_message(body, room.code)
            msg = Message(sender_id=current_user.id, room_id=room.id, body=encrypted_body)
            db.session.add(msg)
            db.session.commit()
            return redirect(url_for('chat', room_id=room.id))

    messages = Message.query.filter_by(room_id=room.id).order_by(Message.timestamp).all()
    for m in messages:
        m.body = decrypt_message(m.body, room.code)

    return render_template('chat.html', room=room, messages=messages)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
    
