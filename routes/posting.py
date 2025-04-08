from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from extensions import mongo
from datetime import datetime
from bson.objectid import ObjectId
from bson import ObjectId
import base64

posting_bp = Blueprint('posting', __name__)
from security.secure_logger import write_secure_log
import time

from flask import redirect, request, flash, session, url_for

@posting_bp.route('/block_user/<target_user_id>', methods=['POST'])
def block_user(target_user_id):
    if 'user_id' not in session:
        flash("Please log in to block users.", "danger")
        return redirect(url_for("auth.login"))

    current_user_id = session["user_id"]

    # Add target user to current user's blocked list (no duplicates)
    mongo.db.users.update_one(
        {"_id": ObjectId(current_user_id)},
        {"$addToSet": {"blocked_users": target_user_id}}
    )

    flash("User has been blocked.", "info")
    return redirect(url_for("posting.view_posts"))

@posting_bp.route('/flag_post/<post_id>', methods=['POST'])
def flag_post(post_id):
    if 'user_id' not in session:
        flash("Please log in to flag posts.", "danger")
        return redirect(url_for('auth.login'))

    # ✅ Rate-limiting block — 3 flags per 5 minutes
    now = time.time()
    recent_flags = session.get("flag_attempts", [])
    recent_flags = [t for t in recent_flags if now - t < 300]  # keep only recent
    if len(recent_flags) >= 3:
        flash("Too many flag attempts. Please wait before flagging again.", "danger")
        return redirect(url_for("posting.view_posts"))
    session["flag_attempts"] = recent_flags + [now]

    # ✅ Proceed with flagging
    username = session.get("username", "anonymous")
    reason = request.form.get("reason", "unspecified")
    details = request.form.get("details", "")

    try:
        mongo.db.flags.insert_one({
            "post_id": post_id,
            "flagged_by": username,
            "reason": reason,
            "details": details,
            "timestamp": time.time()
        })
        write_secure_log("Suspicious Content Flagged", f"Post ID: {post_id}, User: {username}, Reason: {reason}", "Flagged")
        flash("Post flagged for review. Thank you!", "success")
    except Exception as e:
        write_secure_log("Flagging Failed", f"Post ID: {post_id}, User: {username}", f"Error: {str(e)}")
        flash("Something went wrong while flagging the post.", "danger")

    return redirect(url_for("posting.view_posts"))

@posting_bp.route("/add_post")
def add_post():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    return render_template("add_post.html")
import base64

@posting_bp.route('/upload_post', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "You need to log in first."}), 401

    try:
        user_id = ObjectId(session['user_id'])
        user = mongo.db.users.find_one({"_id": user_id})
        if not user:
            return jsonify({"success": False, "message": "User not found."}), 404
    except Exception as e:
        return jsonify({"success": False, "message": "Invalid user ID."}), 400

    image = request.files.get("image")
    caption = request.form.get("caption")

    if not image or not caption:
        return jsonify({"success": False, "message": "Image and caption required."}), 400

    post_id = str(ObjectId())

    # ✅ Convert image to base64 string
    image_data = base64.b64encode(image.read()).decode("utf-8")

    mongo.db.posts.insert_one({
        "post_id": post_id,
        "post_user": user["username"],
        "post_caption": caption,
        "post_image": image_data,  # now stored as base64 string
        "comments": []
    })

    return jsonify({"success": True, "message": "Post uploaded successfully!"}), 200
@posting_bp.route('/view_posts')
def view_posts():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))

    user_id = ObjectId(session["user_id"])
    user_data = mongo.db.users.find_one({"_id": user_id})
    blocked = user_data.get("blocked_users", [])

    # Filter out posts by blocked users
    posts = list(mongo.db.posts.find({"post_user": {"$nin": blocked}}))

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

    return render_template("view_posts.html", posts=formatted_posts)
