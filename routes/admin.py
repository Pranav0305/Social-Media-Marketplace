from flask import Blueprint, render_template, redirect, url_for, request, jsonify, session, flash
from bson import ObjectId  
from extensions import mongo
from gridfs import GridFS 
from flask import send_file
from security.secure_logger import write_secure_log
from flask_mail import Message
from extensions import mail
import random
import time
import os
from security.secure_logger import verify_logs


admin_bp = Blueprint('admin', __name__)

def generate_otp():
    return str(random.randint(100000, 999999))

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
@admin_bp.route('/flagged_posts')
@login_required
def flagged_posts():
    flags = list(mongo.db.flags.find())
    flagged_post_ids = [flag['post_id'] for flag in flags]
    flagged_posts = list(mongo.db.posts.find({"post_id": {"$in": flagged_post_ids}}))
    
    post_flags = {flag["post_id"]: [] for flag in flags}
    for flag in flags:
        post_flags[flag["post_id"]].append({
            "by": flag["flagged_by"],
            "reason": flag["reason"],
            "time": flag["timestamp"]
        })
    
    return render_template("admin_flagged_posts.html", posts=flagged_posts, flags=post_flags)

@admin_bp.route("/verify_log_integrity")
def verify_log_integrity():
    tampered = verify_logs() 
    write_secure_log("Log Integrity Check", ADMIN_USERNAME, f"{'Tampered entries found' if tampered else 'No issues'}")
    return render_template("verify_logs.html", tampered=tampered)

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash("Login successful!", "success")
            write_secure_log("Admin", ADMIN_USERNAME, "logged in")
            return redirect(url_for('admin.dashboard'))
        else:
            flash("Invalid credentials, please try again.", "danger")
    
    return render_template('admin_login.html')

@admin_bp.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    flash("You have been logged out.", "info")
    write_secure_log("Admin", ADMIN_USERNAME, "logged out")
    return redirect(url_for('admin.login'))

@admin_bp.route('/')
def admin_home():
    return redirect(url_for('admin.dashboard'))
LOGS_DIR = 'logs'

@admin_bp.route('/secure_logs')
def secure_logs():
    log_dir = 'logs'
    logs = []

    for filename in sorted(os.listdir(log_dir)):
        if filename.startswith("secure_log_") and filename.endswith(".txt"):
            with open(os.path.join(log_dir, filename), 'r') as f:
                content = f.read()
                logs.append({'filename': filename, 'content': content})
    write_secure_log("Admin Viewed Logs", ADMIN_USERNAME, "Success")

    return render_template('secure_logs.html', logs=logs)


@admin_bp.route('/dashboard')
@login_required
def dashboard():
    users = list(mongo.db.users.find())  
    write_secure_log("Viewed Dashboard", ADMIN_USERNAME, "Success")
    return render_template('admin_dashboard.html', users=users)


@admin_bp.route('/approve_user/<user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    try:
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": "approved"}})
        write_secure_log("Admin Approval", user_id, "User Approved")
        return jsonify({"success": True, "new_status": "approved"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@admin_bp.route('/reject_user/<user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    try:
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": "rejected"}})
        write_secure_log("Admin Rejection", user_id, "User Rejected")
        return jsonify({"success": True, "new_status": "rejected"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@admin_bp.route('/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    try:
        # Remove the user document from the database
        mongo.db.users.delete_one({"_id": ObjectId(user_id)})
        write_secure_log("Admin Deletion", user_id, "User Deleted")
        return jsonify({"success": True, "message": "User deleted successfully."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@admin_bp.route('/document/<document_id>')
@login_required
def view_document(document_id):
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
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/view_posts')
@login_required
def admin_view_posts():
    posts = list(mongo.db.posts.find())
    formatted_posts = [
        {
            "post_id": post.get("post_id"),
            "post_user": post.get("post_user"),
            "caption": post.get("post_caption"),
            "image": post.get("post_image"),
            "comments": post.get("comments", [])
        }
        for post in posts
    ]
    return render_template("admin_view_posts.html", posts=formatted_posts)

@admin_bp.route('/delete_post_request/<post_id>', methods=['GET'])
def initiate_delete_post(post_id):
    otp = generate_otp()
    session['admin_otp'] = otp
    session['admin_otp_post_id'] = post_id
    session['admin_otp_timestamp'] = time.time()

    # Send OTP to admin email
    msg = Message(
        subject="Admin OTP for Post Deletion",
        sender=os.getenv("MAIL_USERNAME"),
        recipients=["socialmediamarketplace137@gmail.com"]
    )
    msg.body = f"""Admin Action Requested:

You are trying to delete post ID: {post_id}

Your OTP is: {otp}
It will expire in 5 minutes.

If this wasn't you, please ignore.
"""
    try:
        mail.send(msg)
        flash("OTP sent to admin email. Please verify to proceed.", "info")
        write_secure_log("Admin OTP Sent", f"Post ID: {post_id}", "Success")

    except Exception as e:
        flash("Failed to send OTP email.", "danger")
        write_secure_log("Admin OTP Sent", f"Post ID: {post_id}", f"Failed - {str(e)}")
        print("OTP send error:", e)
        return redirect(url_for('admin_bp.admin_view_posts'))

    return render_template("admin_verify_otp.html")

@admin_bp.route('/verify_delete_post', methods=['POST'])
def verify_delete_post():
    data = request.get_json()
    entered_otp = data.get('otp')
    post_id = data.get('post_id')

    actual_post_id = session.get('admin_otp_post_id')
    actual_otp = session.get('admin_otp')
    timestamp = session.get('admin_otp_timestamp')

    # Expired OTP
    if not actual_otp or not timestamp or time.time() - timestamp > 300:
        return jsonify({"success": False, "message": "OTP expired. Please request a new one."}), 400

    # Wrong OTP
    if entered_otp != actual_otp:
        write_secure_log("Admin Post Deletion", f"Post ID: {post_id}", "Failed - Incorrect OTP")
        return jsonify({"success": False, "message": "Invalid OTP."}), 401

    # Delete post
    result = mongo.db.posts.delete_one({"post_id": actual_post_id})
    if result.deleted_count > 0:
        write_secure_log("Admin Post Deletion", f"Post ID: {actual_post_id}", "Success")
        message = "Post deleted successfully."
        success = True
    else:
        write_secure_log("Admin Post Deletion", f"Post ID: {actual_post_id}", "Failed - Post not found")
        message = "Post not found."
        success = False

    # Clear session OTP
    session.pop('admin_otp', None)
    session.pop('admin_otp_timestamp', None)
    session.pop('admin_otp_post_id', None)

    return jsonify({
        "success": success,
        "message": message,
        "new_status": "deleted" if success else "not_found"
    })
@admin_bp.route('/ignore_flag/<post_id>', methods=['POST'])
@login_required
def ignore_flag(post_id):
    result = mongo.db.flags.delete_many({"post_id": post_id})
    write_secure_log("Admin Flag Ignored", f"Post ID: {post_id}", f"Removed {result.deleted_count} flags")
    flash("Flag(s) ignored for this post.", "info")
    return redirect(url_for('admin.flagged_posts'))

