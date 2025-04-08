# # from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
# # from extensions import mongo
# # from datetime import datetime
# # from bson.objectid import ObjectId
# # from bson import ObjectId
# # import base64

# # posting_bp = Blueprint('posting', __name__)
# # from security.secure_logger import write_secure_log
# # import time

# # from flask import redirect, request, flash, session, url_for

# # @posting_bp.route('/block_user/<target_user_id>', methods=['POST'])
# # def block_user(target_user_id):
# #     if 'user_id' not in session:
# #         flash("Please log in to block users.", "danger")
# #         return redirect(url_for("auth.login"))

# #     current_user_id = session["user_id"]

# #     # Add target user to current user's blocked list (no duplicates)
# #     mongo.db.users.update_one(
# #         {"_id": ObjectId(current_user_id)},
# #         {"$addToSet": {"blocked_users": target_user_id}}
# #     )

# #     flash("User has been blocked.", "info")
# #     return redirect(url_for("posting.view_posts"))

# # @posting_bp.route('/flag_post/<post_id>', methods=['POST'])
# # def flag_post(post_id):
# #     if 'user_id' not in session:
# #         flash("Please log in to flag posts.", "danger")
# #         return redirect(url_for('auth.login'))

# #     # ✅ Rate-limiting block — 3 flags per 5 minutes
# #     now = time.time()
# #     recent_flags = session.get("flag_attempts", [])
# #     recent_flags = [t for t in recent_flags if now - t < 300]  # keep only recent
# #     if len(recent_flags) >= 3:
# #         flash("Too many flag attempts. Please wait before flagging again.", "danger")
# #         return redirect(url_for("posting.view_posts"))
# #     session["flag_attempts"] = recent_flags + [now]

# #     # ✅ Proceed with flagging
# #     username = session.get("username", "anonymous")
# #     reason = request.form.get("reason", "unspecified")
# #     details = request.form.get("details", "")

# #     try:
# #         mongo.db.flags.insert_one({
# #             "post_id": post_id,
# #             "flagged_by": username,
# #             "reason": reason,
# #             "details": details,
# #             "timestamp": time.time()
# #         })
# #         write_secure_log("Suspicious Content Flagged", f"Post ID: {post_id}, User: {username}, Reason: {reason}", "Flagged")
# #         flash("Post flagged for review. Thank you!", "success")
# #     except Exception as e:
# #         write_secure_log("Flagging Failed", f"Post ID: {post_id}, User: {username}", f"Error: {str(e)}")
# #         flash("Something went wrong while flagging the post.", "danger")

# #     return redirect(url_for("posting.view_posts"))

# # @posting_bp.route("/add_post")
# # def add_post():
# #     if 'user_id' not in session:
# #         flash('Please log in first.')
# #         return redirect(url_for('auth.login'))
# #     return render_template("add_post.html")
# # import base64

# # @posting_bp.route('/upload_post', methods=['POST'])
# # def upload():
# #     if 'user_id' not in session:
# #         return jsonify({"success": False, "message": "You need to log in first."}), 401

# #     try:
# #         user_id = ObjectId(session['user_id'])
# #         user = mongo.db.users.find_one({"_id": user_id})
# #         if not user:
# #             return jsonify({"success": False, "message": "User not found."}), 404
# #     except Exception as e:
# #         return jsonify({"success": False, "message": "Invalid user ID."}), 400

# #     image = request.files.get("image")
# #     caption = request.form.get("caption")

# #     if not image or not caption:
# #         return jsonify({"success": False, "message": "Image and caption required."}), 400

# #     post_id = str(ObjectId())

# #     # ✅ Convert image to base64 string
# #     image_data = base64.b64encode(image.read()).decode("utf-8")

# #     mongo.db.posts.insert_one({
# #         "post_id": post_id,
# #         "post_user": user["username"],
# #         "post_caption": caption,
# #         "post_image": image_data,  # now stored as base64 string
# #         "comments": []
# #     })

# #     return jsonify({"success": True, "message": "Post uploaded successfully!"}), 200
# # @posting_bp.route('/view_posts')
# # def view_posts():
# #     if 'user_id' not in session:
# #         flash('Please log in first.')
# #         return redirect(url_for('auth.login'))

# #     user_id = ObjectId(session["user_id"])
# #     user_data = mongo.db.users.find_one({"_id": user_id})
# #     blocked = user_data.get("blocked_users", [])

# #     # Filter out posts by blocked users
# #     posts = list(mongo.db.posts.find({"post_user": {"$nin": blocked}}))

# #     formatted_posts = [
# #         {
# #             "post_id": post["post_id"],
# #             "post_user": post["post_user"],
# #             "caption": post["post_caption"],
# #             "image": post["post_image"],
# #             "comments": post.get("comments", [])
# #         }
# #         for post in posts
# #     ]

# #     return render_template("view_posts.html", posts=formatted_posts)


# from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
# from extensions import mongo
# from datetime import datetime
# from bson.objectid import ObjectId
# import base64
# import time

# posting_bp = Blueprint('posting', __name__)
# from security.secure_logger import write_secure_log

# @posting_bp.route('/block_user/<target_user_id>', methods=['POST'])
# def block_user(target_user_id):
#     if 'user_id' not in session:
#         flash("Please log in to block users.", "danger")
#         return redirect(url_for("auth.login"))

#     current_user_id = session["user_id"]

#     # Update current user's document by adding the target user ID to blocked_users array
#     mongo.db.users.update_one(
#         {"_id": ObjectId(current_user_id)},
#         {"$addToSet": {"blocked_users": target_user_id}}
#     )

#     flash("User has been blocked.", "info")
#     return redirect(url_for("posting.view_posts"))

# @posting_bp.route('/flag_post/<post_id>', methods=['POST'])
# def flag_post(post_id):
#     if 'user_id' not in session:
#         flash("Please log in to flag posts.", "danger")
#         return redirect(url_for('auth.login'))

#     now = time.time()
#     recent_flags = session.get("flag_attempts", [])
#     recent_flags = [t for t in recent_flags if now - t < 300]
#     if len(recent_flags) >= 3:
#         flash("Too many flag attempts. Please wait before flagging again.", "danger")
#         return redirect(url_for("posting.view_posts"))
#     session["flag_attempts"] = recent_flags + [now]

#     username = session.get("username", "anonymous")
#     reason = request.form.get("reason", "unspecified")
#     details = request.form.get("details", "")

#     try:
#         mongo.db.flags.insert_one({
#             "post_id": post_id,
#             "flagged_by": username,
#             "reason": reason,
#             "details": details,
#             "timestamp": time.time()
#         })
#         write_secure_log("Suspicious Content Flagged", f"Post ID: {post_id}, User: {username}, Reason: {reason}", "Flagged")
#         flash("Post flagged for review. Thank you!", "success")
#     except Exception as e:
#         write_secure_log("Flagging Failed", f"Post ID: {post_id}, User: {username}", f"Error: {str(e)}")
#         flash("Something went wrong while flagging the post.", "danger")

#     return redirect(url_for("posting.view_posts"))

# @posting_bp.route("/add_post")
# def add_post():
#     if 'user_id' not in session:
#         flash('Please log in first.')
#         return redirect(url_for('auth.login'))
#     return render_template("add_post.html")

# @posting_bp.route('/upload_post', methods=['POST'])
# def upload():
#     if 'user_id' not in session:
#         return jsonify({"success": False, "message": "You need to log in first."}), 401

#     try:
#         user_id = ObjectId(session['user_id'])
#         user = mongo.db.users.find_one({"_id": user_id})
#         if not user:
#             return jsonify({"success": False, "message": "User not found."}), 404
#     except Exception as e:
#         return jsonify({"success": False, "message": "Invalid user ID."}), 400

#     image = request.files.get("image")
#     caption = request.form.get("caption")

#     if not image or not caption:
#         return jsonify({"success": False, "message": "Image and caption required."}), 400

#     post_id = str(ObjectId())

#     # Convert image to base64 string
#     image_data = base64.b64encode(image.read()).decode("utf-8")

#     mongo.db.posts.insert_one({
#         "post_id": post_id,
#         "post_user": user["username"],  # storing username for display purposes
#         "post_caption": caption,
#         "post_image": image_data,
#         "comments": []
#     })

#     return jsonify({"success": True, "message": "Post uploaded successfully!"}), 200

# # --- Modified View Posts Route ---
# @posting_bp.route('/view_posts')
# def view_posts():
#     if 'user_id' not in session:
#         flash('Please log in first.')
#         return redirect(url_for('auth.login'))

#     current_user_id = ObjectId(session["user_id"])
#     user_data = mongo.db.users.find_one({"_id": current_user_id})
#     blocked = user_data.get("blocked_users", [])

#     # Convert blocked user IDs (stored as strings) into ObjectIds, then get their usernames
#     blocked_usernames = []
#     if blocked:
#         blocked_users = list(mongo.db.users.find({"_id": {"$in": [ObjectId(uid) for uid in blocked]}}))
#         blocked_usernames = [u["username"] for u in blocked_users]

#     posts = list(mongo.db.posts.find({"post_user": {"$nin": blocked_usernames}}))

#     formatted_posts = [
#         {
#             "post_id": post["post_id"],
#             "post_user": post["post_user"],
#             "caption": post["post_caption"],
#             "image": post["post_image"],
#             "comments": post.get("comments", [])
#         }
#         for post in posts
#     ]

#     return render_template("view_posts.html", posts=formatted_posts)


from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from extensions import mongo
from datetime import datetime
from bson.objectid import ObjectId
import base64
import time

posting_bp = Blueprint('posting', __name__)
<<<<<<< Updated upstream
=======
from security.secure_logger import write_secure_log

@posting_bp.route('/block_user/<target_user_id>', methods=['POST'])
def block_user(target_user_id):
    if 'user_id' not in session:
        flash("Please log in to block users.", "danger")
        return redirect(url_for("auth.login"))

    current_user_id = session["user_id"]

    # Update current user's document by adding the target user ID to blocked_users array
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

    now = time.time()
    recent_flags = session.get("flag_attempts", [])
    recent_flags = [t for t in recent_flags if now - t < 300]
    if len(recent_flags) >= 3:
        flash("Too many flag attempts. Please wait before flagging again.", "danger")
        return redirect(url_for("posting.view_posts"))
    session["flag_attempts"] = recent_flags + [now]

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
>>>>>>> Stashed changes

@posting_bp.route("/add_post")
def add_post():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    return render_template("add_post.html")

@posting_bp.route('/upload_post', methods=['POST'])
def upload():
    if 'user_id' not in session:  
        return jsonify({"message": "User not logged in"}), 401

    try:
        user_id = ObjectId(session['user_id'])  
        user = mongo.db.users.find_one({"_id": user_id})  
    except:
        return jsonify({"message": "Invalid user ID format"}), 400

    if not user:
        return jsonify({"message": "User not found"}), 400
    
    caption = request.form.get("caption")
    image = request.files.get("image")
    username = user.get("username")  # Get username from user document

    if not caption or not image:
        return jsonify({"error": "Missing image or caption"}), 400

    # Convert image to base64
    image_data = base64.b64encode(image.read()).decode('utf-8')
    

    post_id = str(ObjectId())
    post_data = {
        "post_id" : post_id,
        "post_image" : image_data,
        "post_caption" : caption,
        "post_user" : username
    }

<<<<<<< Updated upstream
    mongo.db.posts.insert_one(post_data)
    return jsonify({"message": "Post uploaded", "post_id": str(post_id)}), 201


=======
    # Convert image to base64 string
    image_data = base64.b64encode(image.read()).decode("utf-8")

    mongo.db.posts.insert_one({
        "post_id": post_id,
        "post_user": user["username"],  # storing username for display purposes
        "post_caption": caption,
        "post_image": image_data,
        "comments": []
    })

    return jsonify({"success": True, "message": "Post uploaded successfully!"}), 200

# --- Modified View Posts Route ---
>>>>>>> Stashed changes
@posting_bp.route('/view_posts')
def view_posts():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
<<<<<<< Updated upstream
    posts = list(mongo.db.posts.find())
=======

    current_user_id = session["user_id"]
    user_data = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})

    # Get list of users that current user has blocked (stored as strings)
    blocked_by_me = user_data.get("blocked_users", [])

    # Convert blocked_by_me into usernames
    blocked_by_me_usernames = []
    if blocked_by_me:
        blocked_cursor = mongo.db.users.find({"_id": {"$in": [ObjectId(uid) for uid in blocked_by_me]}})
        blocked_by_me_usernames = [u["username"] for u in blocked_cursor]

    # Find users who have blocked the current user
    blockers_cursor = mongo.db.users.find({"blocked_users": current_user_id})
    blocked_by_others = [u["username"] for u in blockers_cursor]

    # Combine both sets to get the union of usernames to filter out
    union_blocked = set(blocked_by_me_usernames + blocked_by_others)

    posts = list(mongo.db.posts.find({"post_user": {"$nin": list(union_blocked)}}))
>>>>>>> Stashed changes

    formatted_posts = [
        {
            "post_id" : post["post_id"],
            "post_user" : post["post_user"],
            "caption": post["post_caption"], 
            "image": post["post_image"],
            "comments": post.get("comments", [])
         }
        for post in posts
    ]

    return render_template("view_posts.html", posts=formatted_posts)