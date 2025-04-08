from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
import os
from werkzeug.utils import secure_filename
from bson import ObjectId
from extensions import mongo
from gridfs import GridFS

profile_bp = Blueprint('profile_bp', __name__)
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}  # 'pdf' removed since documents are now handled via GridFS
from datetime import datetime


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@profile_bp.route('/send_friend_request/<user_id>', methods=['POST'])
def send_friend_request(user_id):
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('auth.login'))

    from_user_id = ObjectId(session['user_id'])
    mongo.db.friend_requests.insert_one({
        "from_user": from_user_id,
        "to_user": ObjectId(user_id),
        "status": "pending"
    })

    sender = mongo.db.users.find_one({"_id": from_user_id})
    from_username = sender.get("username", "Someone")

    # ✅ Now insert the notification
    mongo.db.notifications.insert_one({
        "user_id": ObjectId(user_id),
        "type": "friend_request",
        "message": f"{from_username} sent you a friend request",
        "timestamp": datetime.utcnow(),
        "is_read": False,
        "link": f"/profile/{from_user_id}"
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
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('auth.login'))

    mongo.db.blocks.insert_one({
        "blocker": ObjectId(session['user_id']),
        "blocked": ObjectId(user_id),
        "timestamp": datetime.utcnow()
    })

    flash("User has been blocked.")
    return redirect(url_for('home.home'))  # or profile_bp.profile
@profile_bp.route('/report_user/<user_id>', methods=['POST'])
def report_user(user_id):
    reason = request.form.get('reason')
    if not reason:
        flash("Please provide a reason for reporting.")
        return redirect(url_for('profile_bp.profile_view_other', user_id=user_id))

    mongo.db.reports.insert_one({
        "reporter": ObjectId(session['user_id']),
        "reported": ObjectId(user_id),
        "reason": reason,
        "timestamp": datetime.utcnow()
    })

    flash("Thank you for reporting. Our team will review the issue.")
    return redirect(url_for('home.home'))  # or some thank-you page

@profile_bp.route('/', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('auth.login'))

    user_id = ObjectId(session['user_id'])
    user_data = mongo.db.users.find_one({"_id": user_id})
    if not user_data:
        flash("User not found.")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        bio = request.form.get('bio')
        file = request.files.get('profile_picture')
        update_fields = {"profile.bio": bio}

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            file.save(file_path)
            update_fields["profile.profile_picture"] = filename

        mongo.db.users.update_one({"_id": user_id}, {"$set": update_fields})
        flash("Profile updated successfully!")
        return redirect(url_for('profile_bp.profile'))

    incoming_requests = mongo.db.friend_requests.find({
        "to_user": user_id,
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

    accepted = mongo.db.friend_requests.find({
        "$or": [
            {"from_user": user_id},
            {"to_user": user_id}
        ],
        "status": "accepted"
    })

    friend_ids = []
    for fr in accepted:
        if fr["from_user"] == user_id:
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
@profile_bp.route('/profile/', methods=['GET', 'POST'])
def profile_view():
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('auth.login'))

    user_id = ObjectId(session['user_id'])
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        flash("User not found.")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        bio = request.form.get('bio')
        profile_picture = request.files.get('profile_picture')

        # Update bio
        mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'profile.bio': bio}})

        # Profile picture via GridFS
        if profile_picture and allowed_file(profile_picture.filename):
            fs = GridFS(mongo.db)

            # Delete old profile picture from GridFS (if it exists)
            prev_filename = user.get("profile", {}).get("profile_picture")
            if prev_filename:
                existing_file = mongo.db.fs.files.find_one({'filename': prev_filename})
                if existing_file:
                    fs.delete(existing_file['_id'])

            # Save new profile picture to GridFS
            filename = secure_filename(profile_picture.filename)
            fs.put(profile_picture, filename=filename, content_type=profile_picture.content_type)
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'profile.profile_picture': filename}})

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile_bp.profile_view'))

    # Re-fetch user after update
    user = mongo.db.users.find_one({'_id': user_id})

    # Build data for template
    incoming_requests = mongo.db.friend_requests.find({
        "to_user": user_id, "status": "pending"
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

    accepted = mongo.db.friend_requests.find({
        "$or": [{"from_user": user_id}, {"to_user": user_id}],
        "status": "accepted"
    })

    friend_ids = [fr["from_user"] if fr["from_user"] != user_id else fr["to_user"] for fr in accepted]
    friends = list(mongo.db.users.find({"_id": {"$in": friend_ids}}))

    return render_template(
        'profile.html',
        user=user,
        is_own_profile=True,
        friend_requests=requests_with_senders,
        friends=friends
    )

@profile_bp.route('/reject_friend_request/<request_id>', methods=['POST'])
def reject_friend_request(request_id):
    mongo.db.friend_requests.delete_one({"_id": ObjectId(request_id)})
    flash("Friend request rejected.")
    return redirect(url_for('profile_bp.profile'))

# === New Route for Viewing Registration Document by the User ===
@profile_bp.route('/document/<document_id>')
def view_document(document_id):
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('auth.login'))
    # Verify that the logged-in user's document matches the requested document ID
    user_data = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    if not user_data or user_data.get("document") != document_id:
        flash("Unauthorized access to document.")
        return redirect(url_for('profile_bp.profile'))
    fs = GridFS(mongo.db)
    try:
        grid_out = fs.get(ObjectId(document_id))
        return send_file(
            grid_out,
            download_name=grid_out.filename,
            mimetype=grid_out.content_type,
            as_attachment=False
        )
    except Exception as e:
        flash("Unable to retrieve document: " + str(e), "danger")
        return redirect(url_for('profile_bp.profile'))
from flask import send_file, abort
from gridfs import GridFS
@profile_bp.route('/profile/<user_id>')
def profile_view_other(user_id):
    try:
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            flash("User not found.")
            return redirect(url_for('profile_bp.profile_view'))

        current_user_id = ObjectId(session['user_id'])
        is_own_profile = (user['_id'] == current_user_id)

        # Load friend requests and friends like before
        # You can reuse the same logic

        return render_template(
            'profile.html',
            user=user,
            is_own_profile=is_own_profile,
            friend_requests=[],
            friends=[]
        )
    except Exception as e:
        flash(f"Invalid user ID.")
        return redirect(url_for('profile_bp.profile_view'))

@profile_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    fs = GridFS(mongo.db)
    file = fs.find_one({'filename': filename})
    if not file:
        abort(404)
    
    return send_file(
        file,
        mimetype=file.content_type,
        download_name=filename  # for Flask 2.2+ compatibility
    )

@profile_bp.route('/my_posts/<user_id>')
def view_user_posts(user_id):
    if 'user_id' not in session:
        flash("Please log in to view posts.")
        return redirect(url_for('auth.login'))

    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash("User not found.")
        return redirect(url_for('home.home'))

    posts = list(mongo.db.posts.find({'post_user': user['username']}))

    formatted_posts = [
        {
            "post_id": post["post_id"],
            "post_user": post["post_user"],
            "caption": post["post_caption"],
            "image": post["post_image"],
            "comments": post.get("comments", [])
        }
        for post in posts
    ]

    return render_template("user_posts.html", posts=formatted_posts, user=user)
