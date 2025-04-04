from flask import Blueprint, render_template, session, redirect, url_for
from extensions import mongo
from bson import ObjectId
from datetime import datetime

notifications_bp = Blueprint('notifications_bp', __name__)

@notifications_bp.route('/notifications')
def view_notifications():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = ObjectId(session['user_id'])

    notifications = list(mongo.db.notifications.find({"user_id": user_id}).sort("timestamp", -1))
    return render_template("notifications.html", notifications=notifications)

@notifications_bp.route('/notifications/read/<notif_id>')
def mark_as_read(notif_id):
    mongo.db.notifications.update_one(
        {"_id": ObjectId(notif_id)},
        {"$set": {"is_read": True}}
    )
    return redirect(url_for('notifications_bp.view_notifications'))
