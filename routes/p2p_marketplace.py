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

@p2p_marketplace_bp.route("/confirm_product", methods = ['GET', 'POST'])
def add_product():
    if request.method == "POST":
        user_id = session['user_id']
        data = request.json
        if not all(key in data for key in ["product_name", "product_seller_username", "product_price", "product_description"]):
            return jsonify({"message": "Missing fields"}), 400

        product_id = str(ObjectId())  # Auto-assign a unique product_id
        product = {
            "_id": product_id,
            "product_name": data["product_name"],
            "product_seller_username": user_id,
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