from flask import Blueprint, render_template, redirect, url_for, request, jsonify, session, flash
from bson import ObjectId  
from extensions import mongo

admin_bp = Blueprint('admin', __name__)

# Hardcoded admin credentials (you can later store these securely in a database or environment variables)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"

def login_required(f):
    def wrap(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash("You must be logged in to access this page.", "danger")
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash("Login successful!", "success")
            return redirect(url_for('admin.dashboard'))
        else:
            flash("Invalid credentials, please try again.", "danger")
    
    return render_template('admin_login.html')

@admin_bp.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('admin.login'))

@admin_bp.route('/')
def admin_home():
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/dashboard')
@login_required
def dashboard():
    users = list(mongo.db.users.find())  
    return render_template('admin_dashboard.html', users=users)

@admin_bp.route('/approve_user/<user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
   
    try:
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": "approved"}})
        return jsonify({"success": True, "new_status": "approved"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@admin_bp.route('/reject_user/<user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    
    try:
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": "rejected"}})
        return jsonify({"success": True, "new_status": "rejected"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
