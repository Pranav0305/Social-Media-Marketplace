from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import mongo

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


UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.email = user_data["email"]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        document = request.files.get('document') 

        existing_user = mongo.db.users.find_one({'username': username})
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('auth.register'))

        hashed_password = generate_password_hash(password)

        
        document_filename = ''
        if document and allowed_file(document.filename):
            document_filename = secure_filename(document.filename)
            document.save(os.path.join(UPLOAD_FOLDER, document_filename))

        user_data = {
            'email': email,
            'username': username,
            'password': hashed_password,
            'status': 'pending',  
            'profile': {
                'profile_picture': '',
                'bio': ''
            },
            'document': document_filename  
        }

        mongo.db.users.insert_one(user_data)
        flash('Registration successful. Please wait for admin approval.')
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
