from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import mongo
import re
auth_bp = Blueprint('auth', __name__)
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from bson import ObjectId
from extensions import mongo
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, UserMixin
from werkzeug.security import check_password_hash
from extensions import mongo
from bson import ObjectId
from gridfs import GridFS

import re 
auth_bp = Blueprint('auth', __name__)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_password(password):
    """Checks if password meets security requirements"""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character (!@#$%^&*())."
    return None  

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        document = request.files.get('document')

        existing_user = mongo.db.users.find_one({'username': username})
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('auth.register'))

        password_error = validate_password(password)
        if password_error:
            flash(password_error, 'danger')
            return redirect(url_for('auth.register'))

        hashed_password = generate_password_hash(password)
        
        # Initialize GridFS instance
        fs = GridFS(mongo.db)
        document_id = None
        
        if document and allowed_file(document.filename):
            filename = secure_filename(document.filename)
            # Save the file to GridFS
            document_id = fs.put(document.read(), filename=filename, content_type=document.content_type)
            print("GridFS file stored with ID:", document_id)  # Debug log
        
        user_data = {
            'email': email,
            'username': username,
            'password': hashed_password,
            'status': 'pending',  # Admin approval required
            'profile': {'profile_picture': '', 'bio': ''},
            'document': str(document_id) if document_id else ''  # Save the GridFS file ID as string
        }

        mongo.db.users.insert_one(user_data)
        flash('Registration successful. Please wait for admin approval.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user_data = mongo.db.users.find_one({'username': username})

        if not user_data:
            flash('Invalid username or password.')
            return redirect(url_for('auth.login'))

        print(f"DEBUG: Found user {user_data['username']} - Stored Password: {user_data['password']}")  
        
        if not check_password_hash(user_data['password'], password):
            flash('Invalid username or password.')
            return redirect(url_for('auth.login'))

        if user_data['status'] != 'approved':
            flash('Your account is not approved yet.')
            return redirect(url_for('auth.login'))

        session['user_id'] = str(user_data["_id"])
        session['username'] = user_data["username"]

        flash('Login successful!')
        return redirect(url_for('profile_bp.profile')) 

    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('auth.login'))
