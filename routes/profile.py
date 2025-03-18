from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import os
from werkzeug.utils import secure_filename
from bson import ObjectId
from extensions import mongo

profile_bp = Blueprint('profile_bp', __name__)
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@profile_bp.route('/profile')
def profile():
    if 'user_id' not in session:  
        flash("You need to log in first.")
        return redirect(url_for('auth.login'))

    user_data = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})

    if not user_data: 
        flash("User not found.")
        return redirect(url_for('auth.login'))

    return render_template('profile.html', user=user_data)  
