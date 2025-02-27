from flask import Blueprint, render_template, redirect, url_for, request, jsonify
from bson import ObjectId  
from extensions import mongo

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/')
def admin_home():
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/dashboard')
def dashboard():
    users = list(mongo.db.users.find())  # Fetch users from MongoDB
    return render_template('admin_dashboard.html', users=users)

@admin_bp.route('/approve_user/<user_id>', methods=['POST'])
def approve_user(user_id):
    try:
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": "approved"}})
        return jsonify({"success": True, "new_status": "approved"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@admin_bp.route('/reject_user/<user_id>', methods=['POST'])
def reject_user(user_id):
    try:
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": "rejected"}})
        return jsonify({"success": True, "new_status": "rejected"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
