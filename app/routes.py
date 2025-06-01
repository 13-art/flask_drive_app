from flask import render_template, request, redirect, url_for, flash, send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, Note
from app import app, db
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.")
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please login.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_folder = os.path.join(app.config['UPLOAD_BASE'], str(current_user.id))
    os.makedirs(user_folder, exist_ok=True)
    files = os.listdir(user_folder)
    return render_template('dashboard.html', files=files)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        user_folder = os.path.join(app.config['UPLOAD_BASE'], str(current_user.id))
        os.makedirs(user_folder, exist_ok=True)
        upload_path = os.path.join(user_folder, filename)
        file.save(upload_path)
        flash('File uploaded successfully.')
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/uploads/<int:user_id>/<filename>')
@login_required
def uploaded_file(user_id, filename):
    if current_user.id != user_id:
        flash("Unauthorized access.")
        return redirect(url_for('dashboard'))

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    return send_from_directory(user_folder, filename)

@app.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    if request.method == 'POST':
        content = request.form['content']
        if content.strip() != "":
            new_note = Note(content=content, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash("Note added.")
        return redirect(url_for('notes'))

    user_notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template('notes.html', notes=user_notes)

@app.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id == current_user.id:
        db.session.delete(note)
        db.session.commit()
        flash("Note deleted.")
    else:
        flash("Unauthorized access.")
    return redirect(url_for('notes'))

@app.route('/delete_file/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    user_folder = os.path.join(app.config['UPLOAD_BASE'], str(current_user.id))
    filepath = os.path.join(user_folder, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        flash(f"{filename} deleted.")
    else:
        flash("File not found.")
    return redirect(url_for('dashboard'))
