import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from flask import render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash


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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match', 'danger')
        elif len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')
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
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        new_note = Note(title=title, content=content, file_name=filename, user_id=current_user.id)
        db.session.add(new_note)
        db.session.commit()

        flash('Note added successfully!', 'success')
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
        if file and file.filename != '':
            # Delete the old file if it exists
            if note.file_name:
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], note.file_name)
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)
            
            # Save the new file
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            note.file_name = filename
        
        db.session.commit()
        flash('Note updated successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('update_note.html', note=note)

from flask import flash, redirect, url_for
import os

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_note(id):
    note = Note.query.get_or_404(id)
    if note.user_id != current_user.id:
        flash('You are not authorized to delete this note.', 'danger')
        return redirect(url_for('index'))

    try:
        if note.file_name:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], note.file_name)
            if os.path.exists(file_path):
                os.remove(file_path)

        db.session.delete(note)
        db.session.commit()
        flash('Note deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the note.', 'danger')
        app.logger.error(f"Error deleting note: {str(e)}")

    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
