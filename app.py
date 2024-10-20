import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_name = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Associate note with a user


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
  
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists. Please login or use another email.', 'danger')
            return redirect(url_for('register'))


        username = email.split('@')[0]
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        

        new_user = User(email=email, username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect(url_for('login'))
        
        login_user(user)
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', notes=notes)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_note():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        file = request.files['file']


        if file:
            file_name = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
        else:
            file_name = None

    
        new_note = Note(title=title, content=content, file_name=file_name, user_id=current_user.id)
        db.session.add(new_note)
        db.session.commit()

        flash('Note added successfully!')
        return redirect(url_for('index'))
    
    return render_template('add_note.html')


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_note(id):
    note = Note.query.get_or_404(id)
    if note.user_id != current_user.id:
        flash('You are not authorized to update this note.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        note.title = request.form['title']
        note.content = request.form['content']
        
        file = request.files['file']
        if file:
            file_name = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
            note.file_name = file_name

        db.session.commit()
        flash('Note updated successfully!')
        return redirect(url_for('index'))
    
    return render_template('update_note.html', note=note)

@app.route('/delete/<int:id>')
@login_required
def delete_note(id):
    note = Note.query.get_or_404(id)
    if note.user_id != current_user.id:
        flash('You are not authorized to delete this note.', 'danger')
        return redirect(url_for('index'))


    if note.file_name:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], note.file_name))

    db.session.delete(note)
    db.session.commit()
    flash('Note deleted successfully!')
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
