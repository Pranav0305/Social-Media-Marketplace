from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from extensions import mongo, mail
from flask_mail import Message
from bson.objectid import ObjectId
from datetime import datetime
import time
import os
from routes.auth import generate_otp

cart_bp = Blueprint('cart', __name__)

# Helper: get or initialize cart in session
def get_cart():
    if 'cart' not in session:
        session['cart'] = []
    return session['cart']

@cart_bp.route("/cart/add/<product_id>")
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('auth.login'))
    # Retrieve product from database
    product = mongo.db.Products.find_one({"_id": product_id})
    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for('marketplace.view_products'))
    cart = get_cart()
    # Optional: check if product already in cart
    for item in cart:
        if item['_id'] == product_id:
            flash("Product already in cart.", "info")
            return redirect(url_for('marketplace.view_products'))
    cart_item = {
        "_id": product_id,
        "product_name": product.get("product_name"),
        "product_price": product.get("product_price"),
        "product_description": product.get("product_description"),
        "product_seller_username": product.get("product_seller_username")
    }
    cart.append(cart_item)
    session['cart'] = cart
    flash("Product added to cart.", "success")
    return redirect(url_for('marketplace.view_products'))

@cart_bp.route("/cart")
def view_cart():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('auth.login'))
    cart = get_cart()
    total = sum(float(item["product_price"]) for item in cart)
    return render_template("cart.html", cart=cart, total=total)

@cart_bp.route("/cart/remove/<product_id>")
def remove_from_cart(product_id):
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('auth.login'))
    cart = get_cart()
    new_cart = [item for item in cart if item['_id'] != product_id]
    session['cart'] = new_cart
    flash("Product removed from cart.", "info")
    return redirect(url_for('cart.view_cart'))

@cart_bp.route("/cart/checkout", methods=["GET", "POST"])
def checkout_cart():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('auth.login'))
    cart = get_cart()
    if not cart:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('marketplace.view_products'))
    total = sum(float(item["product_price"]) for item in cart)
    if request.method == "POST":
        # Initiate OTP for cart payment verification
        otp = generate_otp()
        session['cart_payment_otp'] = otp
        session['cart_payment_otp_timestamp'] = time.time()
        # Send OTP email to buyer
        buyer = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
        msg = Message(
            subject="Your OTP for Cart Payment Verification",
            sender=os.getenv("MAIL_USERNAME"),
            recipients=[buyer['email']]
        )
        msg.body = f"""Hello {buyer['username']},

Your OTP for cart payment verification is: {otp}

This OTP will expire in 5 minutes.

Regards,
Your Platform Team
"""
        try:
            mail.send(msg)
            flash("Payment OTP sent to your email.", "info")
        except Exception as e:
            flash("Failed to send OTP for payment. Please try again.", "danger")
            return redirect(url_for('cart.view_cart'))
        return render_template("verify_cart_payment_otp.html")
    return render_template("checkout.html", cart=cart, total=total)

@cart_bp.route("/cart/complete_payment", methods=["POST"])
def complete_cart_payment():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('auth.login'))
    entered_otp = request.form.get("otp")
    actual_otp = session.get("cart_payment_otp")
    timestamp = session.get("cart_payment_otp_timestamp")
    if not actual_otp or time.time() - timestamp > 300:
         flash("OTP expired. Please try the payment process again.", "danger")
         return redirect(url_for('cart.view_cart'))
    if entered_otp != actual_otp:
         flash("Incorrect OTP. Please try again.", "danger")
         return redirect(url_for('cart.view_cart'))
    
    cart = get_cart()
    buyer = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    buyer_username = buyer["username"]
    
    # Notify each seller for every product in the cart
    for item in cart:
        seller = mongo.db.users.find_one({"username": item["product_seller_username"]})
        if seller:
            mongo.db.notifications.insert_one({
                "user_id": seller["_id"],
                "type": "transaction",
                "message": f"{buyer_username} bought your product: {item['product_name']}",
                "timestamp": datetime.utcnow(),
                "is_read": False,
                "link": "/marketplace"
            })
    
    # Prepare order summary email
    order_details = "\n".join(
        [f"Product: {item['product_name']}, Price: ${item['product_price']}" for item in cart]
    )
    total = sum(float(item["product_price"]) for item in cart)
    msg = Message(
        subject="Your Cart Order Summary",
        sender=os.getenv("MAIL_USERNAME"),
        recipients=[buyer['email']]
    )
    msg.body = f"""Hello {buyer_username},

Thank you for your purchase!

Order Details:
{order_details}
Total: ${total}

Your order will be processed soon.

Regards,
Your Platform Team
"""
    try:
         mail.send(msg)
         flash("Order summary email sent!", "info")
    except Exception as e:
         flash("Purchase complete but failed to send order summary email.", "warning")
    
    # Clear the cart
    session['cart'] = []
    flash("Purchase completed successfully!", "success")
    return redirect(url_for('marketplace.view_products'))
