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
@profile_bp.route('/send_friend_request/<user_id>', methods=['POST'])
def send_friend_request(user_id):
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('auth.login'))

    mongo.db.friend_requests.insert_one({
        "from_user": ObjectId(session['user_id']),
        "to_user": ObjectId(user_id),
        "status": "pending"
    })

    flash("Friend request sent.")
    return redirect(url_for('profile_bp.profile_view', user_id=user_id))
@profile_bp.route('/accept_friend_request/<request_id>', methods=['POST'])
def accept_friend_request(request_id):
    mongo.db.friend_requests.update_one(
        {"_id": ObjectId(request_id)},
        {"$set": {"status": "accepted"}}
    )
    flash("Friend request accepted.")
    return redirect(url_for('profile_bp.profile'))
@profile_bp.route('/block_user/<user_id>', methods=['POST'])
def block_user(user_id):
    mongo.db.blocks.insert_one({
        "blocker": ObjectId(session['user_id']),
        "blocked": ObjectId(user_id)
    })
    flash("User blocked.")
    return redirect(url_for('profile_bp.profile_view', user_id=user_id))
@profile_bp.route('/report_user/<user_id>', methods=['POST'])
def report_user(user_id):
    reason = request.form.get('reason')
    mongo.db.reports.insert_one({
        "reporter": ObjectId(session['user_id']),
        "reported": ObjectId(user_id),
        "reason": reason
    })
    flash("User reported.")
    return redirect(url_for('profile_bp.profile_view', user_id=user_id))
@profile_bp.route('/')
def profile():
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('auth.login'))

    user_data = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    if not user_data:
        flash("User not found.")
        return redirect(url_for('auth.login'))

    # Get incoming friend requests
    incoming_requests = mongo.db.friend_requests.find({
        "to_user": ObjectId(session['user_id']),
        "status": "pending"
    })

    requests_with_senders = []
    for req in incoming_requests:
        sender = mongo.db.users.find_one({"_id": req["from_user"]})
        if sender:
            requests_with_senders.append({
                "request_id": str(req["_id"]),
                "sender_username": sender.get("username"),
                "sender_id": str(sender["_id"])
            })

    # Get accepted friend relationships
    accepted = mongo.db.friend_requests.find({
        "$or": [
            {"from_user": ObjectId(session['user_id'])},
            {"to_user": ObjectId(session['user_id'])}
        ],
        "status": "accepted"
    })

    friend_ids = []
    for fr in accepted:
        if fr["from_user"] == ObjectId(session['user_id']):
            friend_ids.append(fr["to_user"])
        else:
            friend_ids.append(fr["from_user"])

    friends = list(mongo.db.users.find({"_id": {"$in": friend_ids}}))

    return render_template(
        'profile.html',
        user=user_data,
        is_own_profile=True,
        friend_requests=requests_with_senders,
        friends=friends
    )
@profile_bp.route('/<user_id>')
def profile_view(user_id):
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('auth.login'))

    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user_data:
        flash("User not found.")
        return redirect(url_for('profile_bp.profile'))

    is_own_profile = str(session['user_id']) == str(user_id)

    # Get accepted friend relationships for the user being viewed
    accepted = mongo.db.friend_requests.find({
        "$or": [
            {"from_user": ObjectId(user_id)},
            {"to_user": ObjectId(user_id)}
        ],
        "status": "accepted"
    })

    friend_ids = []
    for fr in accepted:
        if fr["from_user"] == ObjectId(user_id):
            friend_ids.append(fr["to_user"])
        else:
            friend_ids.append(fr["from_user"])

    friends = list(mongo.db.users.find({"_id": {"$in": friend_ids}}))


    return render_template(
        'profile.html',
        user=user_data,
        is_own_profile=is_own_profile,
        friends=friends
    )
@profile_bp.route('/reject_friend_request/<request_id>', methods=['POST'])
def reject_friend_request(request_id):
    mongo.db.friend_requests.delete_one({"_id": ObjectId(request_id)})
    flash("Friend request rejected.")
    return redirect(url_for('profile_bp.profile'))

