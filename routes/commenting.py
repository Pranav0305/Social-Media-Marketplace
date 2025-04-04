from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from extensions import mongo
from datetime import datetime
from bson.objectid import ObjectId
from bson import ObjectId
import base64

comment_bp = Blueprint("comment", __name__)

@comment_bp.route("/add_comment", methods=["GET", "POST"])
def add_comment():   
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
    
    data = request.get_json()
    post_id = data.get("post_id")
    comment_text = data.get("text")

    print(post_id)

    if not post_id or not comment_text:
        return jsonify({"success": False, "message": "Missing data"}), 400
    
    comment = {
        "username": username,
        "text": comment_text
    }

    # Insert comment into the correct post
    mongo.db.posts.update_one(
        {"post_id": ObjectId(post_id)},
        {"$push": {"comments": comment}}
    )

    return jsonify({"success": True, "username": username})
