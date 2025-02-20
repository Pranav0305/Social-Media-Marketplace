from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import mongo

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        
        existing_user = mongo.db.users.find_one({'username': username})
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('auth.register'))
            
        
        hashed_password = generate_password_hash(password)
        
        user_data = {
            'email': email,
            'username': username,
            'password': hashed_password,
            'status': 'pending',  
            'profile': {
                'profile_picture': '',
                'bio': ''
            }
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
        
        user = mongo.db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            if user['status'] != 'approved':
                flash('Your account is not approved yet.')
                return redirect(url_for('auth.login'))
            
            
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            flash('Login successful!')
            return redirect(url_for('profile.profile'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('auth.login'))
            
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('auth.login'))
