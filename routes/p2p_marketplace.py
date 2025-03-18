from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from extensions import mongo
from datetime import datetime
from bson.objectid import ObjectId

p2p_marketplace_bp = Blueprint('marketplace', __name__)

@p2p_marketplace_bp.route("/add_product")
def marketplace():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    return render_template("add_product.html")
from bson import ObjectId
@p2p_marketplace_bp.route("/confirm_product", methods=['POST'])
def add_product():
    if 'user_id' not in session:  
        return jsonify({"message": "User not logged in"}), 401

    try:
        user_id = ObjectId(session['user_id'])  # Convert session user_id to ObjectId
        user = mongo.db.users.find_one({"_id": user_id})  # Query using ObjectId
    except:
        return jsonify({"message": "Invalid user ID format"}), 400

    if not user:
        return jsonify({"message": "User not found"}), 400

    username = user.get("username")  # Get username from user document
    data = request.json

    if not all(key in data for key in ["product_name", "product_price", "product_description"]):
        return jsonify({"message": "Missing fields"}), 400

    product_id = str(ObjectId())  # Assign a unique product_id
    product = {
        "_id": product_id,
        "product_name": data["product_name"],
        "product_seller_username": username,  # Store the correct username
        "product_price": data["product_price"],
        "product_description": data["product_description"]
    }

    mongo.db.Products.insert_one(product)
    return jsonify({"message": "Product added successfully!", "product_id": product_id})

@p2p_marketplace_bp.route("/view_products")
def view_products():
    products = list(mongo.db.Products.find({}))  # Fetch all products from MongoDB

    # Convert ObjectId to string for JSON serialization
    for product in products:
        product["_id"] = str(product["_id"])

    return render_template("view_products.html", products=products)

@p2p_marketplace_bp.route("/buy/<product_id>")
def buy_product(product_id):
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    
    product = mongo.db.Products.find_one({"_id": product_id})
    if not product:
        return "Product not found", 404
    return render_template("payment_gateway.html", product=product)
