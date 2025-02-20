from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from bson.objectid import ObjectId
from extensions import mongo

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    if request.method == 'POST':
        username = request.form.get('username')
        bio = request.form.get('bio')
        
        mongo.db.users.update_one({'_id': ObjectId(session['user_id'])}, {'$set': {'username': username, 'profile.bio': bio}})
        flash('Profile updated successfully.')
        return redirect(url_for('profile.profile'))
    
    return render_template('profile.html', user=user)
