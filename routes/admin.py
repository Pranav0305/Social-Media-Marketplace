from flask import Blueprint, render_template, request, redirect, url_for, flash
from bson.objectid import ObjectId
from extensions import mongo

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/')
def dashboard():
    users = list(mongo.db.users.find())
    return render_template('admin_dashboard.html', users=users)

@admin_bp.route('/approve/<user_id>', methods=['POST'])
def approve_user(user_id):
    mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'status': 'approved'}})
    flash('User approved successfully.')
    return redirect(url_for('admin.dashboard'))
