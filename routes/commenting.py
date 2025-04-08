from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from extensions import mongo
from datetime import datetime
from bson.objectid import ObjectId
from bson import ObjectId
import base64

comment_bp = Blueprint("comment", __name__)

@comment_bp.route("/add_comment/<post_id>", methods=["GET", "POST"])
def add_comment(post_id):   
    if 'user_id' not in session:  
        return jsonify({"message": "User not logged in"}), 401

    try:
        user_id = ObjectId(session['user_id'])  
        user = mongo.db.users.find_one({"_id": user_id})  
    except:
        return jsonify({"message": "Invalid user ID format"}), 400

    if not user:
        return jsonify({"message": "User not found"}), 400
    
    username = user.get("username")


    comment_text = request.form.get("text")
    if not comment_text:
        flash("Comment cannot be empty.")
        return redirect(url_for("posting.view_posts"))

    comment = {
        "username": user.get("username"),
        "text": comment_text
    }

    mongo.db.posts.update_one(
        {"post_id": post_id},
        {"$push": {"comments": comment}}
    )

    flash("Comment added successfully.")
    return redirect(url_for("posting.view_posts"))