# # from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
# # from extensions import mongo
# # from datetime import datetime
# # from bson.objectid import ObjectId

# # p2p_marketplace_bp = Blueprint('marketplace', __name__)

# # @p2p_marketplace_bp.route("/add_product")
# # def marketplace():
# #     if 'user_id' not in session:
# #         flash('Please log in first.')
# #         return redirect(url_for('auth.login'))
# #     return render_template("add_product.html")
# # from bson import ObjectId

# # @p2p_marketplace_bp.route("/confirm_product", methods=['POST'])
# # def add_product():
# #     if 'user_id' not in session:  
# #         return jsonify({"message": "User not logged in"}), 401

# #     try:
# #         user_id = ObjectId(session['user_id'])  # Convert session user_id to ObjectId
# #         user = mongo.db.users.find_one({"_id": user_id})  # Query using ObjectId
# #     except:
# #         return jsonify({"message": "Invalid user ID format"}), 400

# #     if not user:
# #         return jsonify({"message": "User not found"}), 400

# #     username = user.get("username")  # Get username from user document
# #     data = request.json

# #     if not all(key in data for key in ["product_name", "product_price", "product_description"]):
# #         return jsonify({"message": "Missing fields"}), 400

# #     product_id = str(ObjectId())  # Assign a unique product_id
# #     product = {
# #         "_id": product_id,
# #         "product_name": data["product_name"],
# #         "product_seller_username": username,  # Store the correct username
# #         "product_price": data["product_price"],
# #         "product_description": data["product_description"]
# #     }

# #     mongo.db.Products.insert_one(product)
# #     return jsonify({"message": "Product added successfully!", "product_id": product_id})

# # # @p2p_marketplace_bp.route("/view_products")
# # # def view_products():
# # #     products = list(mongo.db.Products.find({}))  # Fetch all products from MongoDB

# # #     # Convert ObjectId to string for JSON serialization
# # #     for product in products:
# # #         product["_id"] = str(product["_id"])

# # #     return render_template("view_products.html", products=products)

# # @p2p_marketplace_bp.route("/view_products")
# # def view_products():
# #     # If 'user_id' not in session, optionally enforce login
# #     # if 'user_id' not in session:
# #     #     flash('Please log in first.')
# #     #     return redirect(url_for('auth.login'))

# #     search_query = request.args.get('search', '').strip()

# #     if search_query:
# #         # Use case-insensitive regex to search product_name OR product_description
# #         query = {
# #             "$or": [
# #                 {"product_name": {"$regex": search_query, "$options": "i"}},
# #                 {"product_description": {"$regex": search_query, "$options": "i"}}
# #             ]
# #         }
# #         products_cursor = mongo.db.Products.find(query)
# #     else:
# #         # No search term -> retrieve all products
# #         products_cursor = mongo.db.Products.find({})

# #     products = list(products_cursor)

# #     # Convert ObjectIds to strings for each product
# #     for product in products:
# #         if isinstance(product["_id"], ObjectId):
# #             product["_id"] = str(product["_id"])

# #     return render_template("view_products.html", products=products, search_query=search_query)


# # @p2p_marketplace_bp.route("/buy/<product_id>")
# # def buy_product(product_id):
# #     if 'user_id' not in session:
# #         flash('Please log in first.')
# #         return redirect(url_for('auth.login'))
    
# #     product = mongo.db.Products.find_one({"_id": product_id})
# #     if not product:
# #         return "Product not found", 404
# #     return render_template("payment_gateway.html", product=product)
# # @p2p_marketplace_bp.route("/complete_purchase/<product_id>", methods=["POST"])
# # def complete_purchase(product_id):
# #     if 'user_id' not in session:
# #         flash('Please log in first.')
# #         return redirect(url_for('auth.login'))

# #     buyer_id = ObjectId(session['user_id'])
# #     buyer = mongo.db.users.find_one({"_id": buyer_id})
# #     buyer_username = buyer["username"]

# #     product = mongo.db.Products.find_one({"_id": product_id})
# #     if not product:
# #         flash("Product not found.")
# #         return redirect(url_for('marketplace.view_products'))

# #     seller_username = product["product_seller_username"]
# #     seller = mongo.db.users.find_one({"username": seller_username})
# #     seller_id = seller["_id"]

# #     # ✅ Notify the seller
# #     mongo.db.notifications.insert_one({
# #         "user_id": ObjectId(seller_id),
# #         "type": "transaction",
# #         "message": f"{buyer_username} bought your product: {product['product_name']}",
# #         "timestamp": datetime.utcnow(),
# #         "is_read": False,
# #         "link": "/marketplace"
# #     })

# #     flash("Purchase completed! The seller has been notified.")
# #     return redirect(url_for('marketplace.view_products'))

# from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
# from extensions import mongo, mail
# from datetime import datetime
# from bson.objectid import ObjectId
# import time
# import os
# from flask_mail import Message
# from routes.auth import generate_otp  # Reusing OTP generation from auth.py

# p2p_marketplace_bp = Blueprint('marketplace', __name__)

# # ---------------- Existing Marketplace Endpoints ----------------

# @p2p_marketplace_bp.route("/add_product")
# def marketplace():
#     if 'user_id' not in session:
#         flash('Please log in first.')
#         return redirect(url_for('auth.login'))
#     return render_template("add_product.html")


# @p2p_marketplace_bp.route("/confirm_product", methods=['POST'])
# def add_product():
#     if 'user_id' not in session:
#         return jsonify({"message": "User not logged in"}), 401

#     try:
#         user_id = ObjectId(session['user_id'])
#         user = mongo.db.users.find_one({"_id": user_id})
#     except Exception as e:
#         return jsonify({"message": "Invalid user ID format"}), 400

#     if not user:
#         return jsonify({"message": "User not found"}), 400

#     username = user.get("username")
#     data = request.json

#     if not all(key in data for key in ["product_name", "product_price", "product_description"]):
#         return jsonify({"message": "Missing fields"}), 400

#     product_id = str(ObjectId())
#     product = {
#         "_id": product_id,
#         "product_name": data["product_name"],
#         "product_seller_username": username,
#         "product_price": data["product_price"],
#         "product_description": data["product_description"]
#     }

#     mongo.db.Products.insert_one(product)
#     return jsonify({"message": "Product added successfully!", "product_id": product_id})


# @p2p_marketplace_bp.route("/view_products")
# def view_products():
#     search_query = request.args.get('search', '').strip()
#     if search_query:
#         query = {
#             "$or": [
#                 {"product_name": {"$regex": search_query, "$options": "i"}},
#                 {"product_description": {"$regex": search_query, "$options": "i"}}
#             ]
#         }
#         products_cursor = mongo.db.Products.find(query)
#     else:
#         products_cursor = mongo.db.Products.find({})
#     products = list(products_cursor)
#     for product in products:
#         if isinstance(product["_id"], ObjectId):
#             product["_id"] = str(product["_id"])
#     return render_template("view_products.html", products=products, search_query=search_query)


# @p2p_marketplace_bp.route("/buy/<product_id>")
# def buy_product(product_id):
#     if 'user_id' not in session:
#         flash('Please log in first.')
#         return redirect(url_for('auth.login'))
#     product = mongo.db.Products.find_one({"_id": product_id})
#     if not product:
#         return "Product not found", 404
#     return render_template("payment_gateway.html", product=product)


# # ---------------- New OTP Payment Endpoints ----------------

# @p2p_marketplace_bp.route("/initiate_payment/<product_id>", methods=["POST"])
# def initiate_payment(product_id):
#     if 'user_id' not in session:
#         flash('Please log in first.')
#         return redirect(url_for('auth.login'))
    
#     # Retrieve product and buyer details
#     product = mongo.db.Products.find_one({"_id": product_id})
#     if not product:
#         flash("Product not found.")
#         return redirect(url_for('marketplace.view_products'))

#     buyer = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
#     if not buyer:
#         flash("User not found.")
#         return redirect(url_for('auth.login'))
    
#     # Generate and store OTP for payment verification
#     otp = generate_otp()
#     session['payment_otp'] = otp
#     session['payment_otp_timestamp'] = time.time()
#     session['payment_product_id'] = product_id  # Store product id for later use

#     # Send OTP email to buyer
#     msg = Message(
#         subject="Your OTP for Payment Verification",
#         sender=os.getenv("MAIL_USERNAME"),
#         recipients=[buyer['email']]
#     )
#     msg.body = f"""Hello {buyer['username']},

# Your OTP for payment verification is: {otp}

# This OTP will expire in 5 minutes.

# Regards,
# Your Platform Team
# """
#     try:
#         mail.send(msg)
#         flash("Payment OTP sent to your email.", "info")
#     except Exception as e:
#         flash("Failed to send OTP for payment. Please try again.", "danger")
#         return redirect(url_for('marketplace.buy_product', product_id=product_id))

#     # Render the OTP verification page for payment
#     return render_template("verify_payment_otp.html", product_id=product_id)

# @p2p_marketplace_bp.route("/complete_payment/<product_id>", methods=["POST"])
# def complete_payment(product_id):
#     if 'user_id' not in session:
#         flash('Please log in first.')
#         return redirect(url_for('auth.login'))

#     # --- OTP Verification ---
#     entered_otp = request.form.get("otp")
#     actual_otp = session.get("payment_otp")
#     timestamp = session.get("payment_otp_timestamp")
    
#     if not actual_otp or time.time() - timestamp > 300:
#         flash("OTP expired. Please try the payment process again.", "danger")
#         return redirect(url_for('marketplace.buy_product', product_id=product_id))
    
#     if entered_otp != actual_otp:
#         flash("Incorrect OTP. Please try again.", "danger")
#         return redirect(url_for('marketplace.buy_product', product_id=product_id))

#     # --- Get Buyer Info ---
#     buyer_id = ObjectId(session['user_id'])
#     buyer = mongo.db.users.find_one({"_id": buyer_id})
#     if not buyer:
#         flash("Buyer not found.")
#         return redirect(url_for('marketplace.view_products'))

#     buyer_username = buyer.get("username")
#     buyer_email = buyer.get("email")

#     # --- Get Product Info ---
#     product = mongo.db.Products.find_one({"_id": product_id})
#     if not product:
#         flash("Product not found.")
#         return redirect(url_for('marketplace.view_products'))

#     product_name = product.get("product_name")
#     product_price = product.get("product_price")
#     seller_username = product.get("product_seller_username")

#     # --- Get Seller Info ---
#     seller = mongo.db.users.find_one({"username": seller_username})
#     if not seller:
#         flash("Seller not found. Notification could not be sent.", "warning")
#         return redirect(url_for('marketplace.view_products'))

#     seller_id = seller["_id"]

#     # ✅ Insert Notification for Seller
#     mongo.db.notifications.insert_one({
#         "user_id": seller_id,
#         "type": "transaction",
#         "message": f"{buyer_username} bought your product: {product_name}",
#         "timestamp": datetime.utcnow(),
#         "is_read": False,
#         "link": "/marketplace"
#     })

#     # ✅ Email Order Summary to Buyer
#     try:
#         msg = Message(
#             subject="Your Order Summary",
#             sender=os.getenv("MAIL_USERNAME"),
#             recipients=[buyer_email]
#         )
#         msg.body = f"""Hello {buyer_username},

# Thank you for your purchase!

# Order Details:
# Product: {product_name}
# Price: ${product_price}

# Your order will be processed soon.

# Regards,
# Your Platform Team
# """
#         mail.send(msg)
#         flash("Order summary email sent!", "info")
#     except Exception as e:
#         flash("Purchase completed but failed to send order summary email.", "warning")

#     # ✅ Cleanup OTP session info
#     session.pop('payment_otp', None)
#     session.pop('payment_otp_timestamp', None)
#     session.pop('payment_product_id', None)

#     flash("Purchase completed successfully!", "success")
#     return redirect(url_for('marketplace.view_products'))


from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from extensions import mongo, mail
from datetime import datetime
from bson.objectid import ObjectId
import time
import os
from flask_mail import Message
from routes.auth import generate_otp  # Reusing OTP generation from auth.py

p2p_marketplace_bp = Blueprint('marketplace', __name__)

# ---------------- Existing Marketplace Endpoints ----------------

@p2p_marketplace_bp.route("/add_product")
def marketplace():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    return render_template("add_product.html")


@p2p_marketplace_bp.route("/confirm_product", methods=['POST'])
def add_product():
    if 'user_id' not in session:
        flash('Please log in first.', "warning")
        return redirect(url_for('auth.login'))

    try:
        user_id = ObjectId(session['user_id'])
        user = mongo.db.users.find_one({"_id": user_id})
    except Exception as e:
        flash("Invalid user ID format", "danger")
        return redirect(url_for('marketplace.marketplace'))

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('auth.login'))

    username = user.get("username")
    # Retrieve form data instead of JSON data
    data = request.form

    # Ensure the required fields are present
    if not all(key in data for key in ["product_name", "product_price", "product_description"]):
        flash("Missing required fields. Please fill in all the details.", "danger")
        return redirect(url_for('marketplace.marketplace'))

    product_id = str(ObjectId())
    product = {
        "_id": product_id,
        "product_name": data["product_name"],
        "product_seller_username": username,
        "product_price": data["product_price"],
        "product_description": data["product_description"]
    }

    mongo.db.Products.insert_one(product)
    flash("Product added successfully!", "success")
    return redirect(url_for('marketplace.view_products'))


@p2p_marketplace_bp.route("/view_products")
def view_products():
    search_query = request.args.get('search', '').strip()
    if search_query:
        query = {
            "$or": [
                {"product_name": {"$regex": search_query, "$options": "i"}},
                {"product_description": {"$regex": search_query, "$options": "i"}}
            ]
        }
        products_cursor = mongo.db.Products.find(query)
    else:
        products_cursor = mongo.db.Products.find({})
    products = list(products_cursor)
    for product in products:
        # Convert ObjectId to string (if needed)
        if isinstance(product.get("_id"), ObjectId):
            product["_id"] = str(product["_id"])
    return render_template("view_products.html", products=products, search_query=search_query)


@p2p_marketplace_bp.route("/buy/<product_id>")
def buy_product(product_id):
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    product = mongo.db.Products.find_one({"_id": product_id})
    if not product:
        return "Product not found", 404
    return render_template("payment_gateway.html", product=product)

# ---------------- New OTP Payment Endpoints ----------------

@p2p_marketplace_bp.route("/initiate_payment/<product_id>", methods=["POST"])
def initiate_payment(product_id):
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    
    # Retrieve product and buyer details
    product = mongo.db.Products.find_one({"_id": product_id})
    if not product:
        flash("Product not found.")
        return redirect(url_for('marketplace.view_products'))

    buyer = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    if not buyer:
        flash("User not found.")
        return redirect(url_for('auth.login'))
    
    # Generate and store OTP for payment verification
    otp = generate_otp()
    session['payment_otp'] = otp
    session['payment_otp_timestamp'] = time.time()
    session['payment_product_id'] = product_id  # Store product id for later use

    # Send OTP email to buyer
    msg = Message(
        subject="Your OTP for Payment Verification",
        sender=os.getenv("MAIL_USERNAME"),
        recipients=[buyer['email']]
    )
    msg.body = f"""Hello {buyer['username']},

Your OTP for payment verification is: {otp}

This OTP will expire in 5 minutes.

Regards,
Your Platform Team
"""
    try:
        mail.send(msg)
        flash("Payment OTP sent to your email.", "info")
    except Exception as e:
        flash("Failed to send OTP for payment. Please try again.", "danger")
        return redirect(url_for('marketplace.buy_product', product_id=product_id))

    # Render the OTP verification page for payment
    return render_template("verify_payment_otp.html", product_id=product_id)


@p2p_marketplace_bp.route("/complete_payment/<product_id>", methods=["POST"])
def complete_payment(product_id):
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))

    # --- OTP Verification ---
    entered_otp = request.form.get("otp")
    actual_otp = session.get("payment_otp")
    timestamp = session.get("payment_otp_timestamp")
    
    if not actual_otp or time.time() - timestamp > 300:
        flash("OTP expired. Please try the payment process again.", "danger")
        return redirect(url_for('marketplace.buy_product', product_id=product_id))
    
    if entered_otp != actual_otp:
        flash("Incorrect OTP. Please try again.", "danger")
        return redirect(url_for('marketplace.buy_product', product_id=product_id))

    # --- Get Buyer Info ---
    buyer_id = ObjectId(session['user_id'])
    buyer = mongo.db.users.find_one({"_id": buyer_id})
    if not buyer:
        flash("Buyer not found.")
        return redirect(url_for('marketplace.view_products'))

    buyer_username = buyer.get("username")
    buyer_email = buyer.get("email")

    # --- Get Product Info ---
    product = mongo.db.Products.find_one({"_id": product_id})
    if not product:
        flash("Product not found.")
        return redirect(url_for('marketplace.view_products'))

    product_name = product.get("product_name")
    product_price = product.get("product_price")
    seller_username = product.get("product_seller_username")

    # --- Get Seller Info ---
    seller = mongo.db.users.find_one({"username": seller_username})
    if not seller:
        flash("Seller not found. Notification could not be sent.", "warning")
        return redirect(url_for('marketplace.view_products'))

    seller_id = seller["_id"]

    # Insert Notification for Seller
    mongo.db.notifications.insert_one({
        "user_id": seller_id,
        "type": "transaction",
        "message": f"{buyer_username} bought your product: {product_name}",
        "timestamp": datetime.utcnow(),
        "is_read": False,
        "link": "/marketplace"
    })

    # Email Order Summary to Buyer
    try:
        msg = Message(
            subject="Your Order Summary",
            sender=os.getenv("MAIL_USERNAME"),
            recipients=[buyer_email]
        )
        msg.body = f"""Hello {buyer_username},

Thank you for your purchase!

Order Details:
Product: {product_name}
Price: ${product_price}

Your order will be processed soon.

Regards,
Your Platform Team
"""
        mail.send(msg)
        flash("Order summary email sent!", "info")
    except Exception as e:
        flash("Purchase completed but failed to send order summary email.", "warning")

    # Cleanup OTP session info
    session.pop('payment_otp', None)
    session.pop('payment_otp_timestamp', None)
    session.pop('payment_product_id', None)

    flash("Purchase completed successfully!", "success")
    return redirect(url_for('marketplace.view_products'))

