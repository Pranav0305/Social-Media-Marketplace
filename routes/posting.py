from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from extensions import mongo
from datetime import datetime
from bson.objectid import ObjectId
from bson import ObjectId
import base64

posting_bp = Blueprint('posting', __name__)

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

    mongo.db.posts.insert_one(post_data)
    return jsonify({"message": "Post uploaded", "post_id": str(post_id)}), 201


@posting_bp.route('/view_posts')
def view_posts():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    posts = list(mongo.db.posts.find())

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