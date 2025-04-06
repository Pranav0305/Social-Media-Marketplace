# from flask import Blueprint, render_template, request, redirect, url_for, flash, session
# from werkzeug.security import generate_password_hash, check_password_hash
# from werkzeug.utils import secure_filename
# from extensions import mongo
# import re
# from bson import ObjectId
# from gridfs import GridFS
# from security.secure_logger import write_secure_log

# auth_bp = Blueprint('auth', __name__)

# ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# def validate_password(password):
#     """Checks if password meets security requirements"""
#     if len(password) < 8:
#         return "Password must be at least 8 characters long."
#     if not re.search(r"[A-Z]", password):
#         return "Password must contain at least one uppercase letter."
#     if not re.search(r"[a-z]", password):
#         return "Password must contain at least one lowercase letter."
#     if not re.search(r"\d", password):
#         return "Password must contain at least one number."
#     if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
#         return "Password must contain at least one special character (!@#$%^&*())."
#     return None  

# @auth_bp.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         username = request.form.get('username')
#         password = request.form.get('password')
#         document = request.files.get('document')

#         existing_user = mongo.db.users.find_one({'username': username})
#         if existing_user:
#             flash('Username already exists. Please choose a different one.', 'danger')
#             return redirect(url_for('auth.register'))

#         password_error = validate_password(password)
#         if password_error:
#             flash(password_error, 'danger')
#             return redirect(url_for('auth.register'))

#         hashed_password = generate_password_hash(password)
        
#         # Initialize GridFS instance
#         fs = GridFS(mongo.db)
#         document_id = None
        
#         if document and allowed_file(document.filename):
#             filename = secure_filename(document.filename)
#             # Save the file to GridFS
#             document_id = fs.put(document.read(), filename=filename, content_type=document.content_type)
#             print("GridFS file stored with ID:", document_id)  # Debug log
        
#         user_data = {
#             'email': email,
#             'username': username,
#             'password': hashed_password,
#             'status': 'pending',  # Admin approval required for certain functionalities
#             'profile': {'profile_picture': '', 'bio': ''},
#             'document': str(document_id) if document_id else ''  # Save the GridFS file ID as string
#         }

#         mongo.db.users.insert_one(user_data)
#         flash('Registration successful. Please wait for admin approval.', 'success')
#         write_secure_log("User Registered", username, "Success")
#         return redirect(url_for('auth.login'))

#     return render_template('register.html')


# @auth_bp.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         user_data = mongo.db.users.find_one({'username': username})

#         if not user_data:
#             flash('Invalid username or password.')
#             write_secure_log("User Login", username, "Failed")
#             return redirect(url_for('auth.login'))
#         write_secure_log("User Login", username, "Success")
#         print(f"DEBUG: Found user {user_data['username']} - Stored Password: {user_data['password']}")  
        
#         if not check_password_hash(user_data['password'], password):
#             flash('Invalid username or password.')
#             return redirect(url_for('auth.login'))

#         # Allow login regardless of approval status, but store the status in the session.
#         session['user_id'] = str(user_data["_id"])
#         session['username'] = user_data["username"]
#         session['status'] = user_data.get("status", "pending")  # e.g., 'approved' or 'pending'

#         flash('Login successful!')
#         return redirect(url_for('profile_bp.profile')) 

#     return render_template('login.html')


# @auth_bp.route('/logout')
# def logout():
#     session.clear()
#     flash('Logged out successfully.')
#     return redirect(url_for('auth.login'))


from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from extensions import mongo
import re
from bson import ObjectId
from gridfs import GridFS
from security.secure_logger import write_secure_log
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import os
import base64
import random
from flask_mail import Message
from extensions import mail


def generate_otp():
    return str(random.randint(100000, 999999))


auth_bp = Blueprint('auth', __name__)
@auth_bp.route("/test-email")
def test_email():
    msg = Message(
        "Flask-Mail Test",
        sender=os.getenv("MAIL_USERNAME"),
        recipients=["sinha.annika@gmail.com"],
        body="If you're seeing this, Flask-Mail is working! 🎉"
    )
    try:
        mail.send(msg)
        return "✅ Email sent!"
    except Exception as e:
        return f"❌ Failed to send: {e}"

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_password(password):
    """Checks if password meets security requirements"""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character (!@#$%^&*())."
    return None  
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        document = request.files.get('document')

        existing_user = mongo.db.users.find_one({'username': username})
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('auth.register'))

        password_error = validate_password(password)
        if password_error:
            flash(password_error, 'danger')
            return redirect(url_for('auth.register'))

        # Hash password for future login
        hashed_password = generate_password_hash(password)

        # ===== GridFS Document Upload =====
        fs = GridFS(mongo.db)
        document_id = None
        if document and allowed_file(document.filename):
            filename = secure_filename(document.filename)
            document_id = fs.put(document.read(), filename=filename, content_type=document.content_type)

        # ===== RSA Key Generation =====
        rsa_key = RSA.generate(2048)
        private_key = rsa_key.export_key()
        public_key = rsa_key.publickey().export_key()

        salt = os.urandom(16)
        aes_key = PBKDF2(password, salt, dkLen=32, count=100000)
        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(private_key)
        encrypted_private_key = {
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }

        # Final user data to insert
        user_data = {
            'email': email,
            'username': username,
            'password': hashed_password,
            'status': 'pending',
            'profile': {'profile_picture': '', 'bio': ''},
            'document': str(document_id) if document_id else '',
            'public_key': public_key.decode(),
            'encrypted_private_key': encrypted_private_key
        }

        mongo.db.users.insert_one(user_data)
        flash('Registration successful! You may now log in.', 'success')
        write_secure_log("User Registered", username, "Success")
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        actual_otp = session.get('otp')
        timestamp = session.get('otp_timestamp')

        if not actual_otp or time.time() - timestamp > 300:
            flash("OTP expired. Please register again.", "danger")
            return redirect(url_for('auth.register'))

        if entered_otp != actual_otp:
            flash("Incorrect OTP. Try again.", "danger")
            return redirect(url_for('auth.verify_otp'))

        user_data = session.pop('pending_user', None)
        if user_data:
            mongo.db.users.insert_one(user_data)
            write_secure_log("User Registered", user_data['username'], "Success")
            flash("Registration successful. You may now login.", "success")
            return redirect(url_for('auth.login'))

        flash("Session expired. Please register again.", "danger")
        return redirect(url_for('auth.register'))

    return render_template('verify_otp.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user_data = mongo.db.users.find_one({'username': username})

        if not user_data:
            flash('Invalid username or password.')
            write_secure_log("User Login", username, "Failed")
            return redirect(url_for('auth.login'))
        
        if not check_password_hash(user_data['password'], password):
            flash('Invalid username or password.')
            write_secure_log("User Login", username, "Failed")
            return redirect(url_for('auth.login'))

        # ===== Decrypt the Encrypted Private Key for E2E decryption =====
        try:
            encrypted_private_key = user_data['encrypted_private_key']
            salt = base64.b64decode(encrypted_private_key['salt'])
            nonce = base64.b64decode(encrypted_private_key['nonce'])
            ciphertext = base64.b64decode(encrypted_private_key['ciphertext'])
            tag = base64.b64decode(encrypted_private_key['tag'])
            # Derive the AES key using the provided password and the stored salt
            aes_key = PBKDF2(password, salt, dkLen=32, count=100000)
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            decrypted_private_key = cipher.decrypt_and_verify(ciphertext, tag)
            # Store the decrypted private key in session (note: in production, handle with care)
            session['private_key'] = decrypted_private_key.decode()
        except Exception as e:
            flash("Error decrypting private key. Please check your password.")
            return redirect(url_for('auth.login'))
        # ===============================================================

        # Store user info in session
        # Store user info in session
        session['user_id'] = str(user_data["_id"])
        session['username'] = user_data["username"]
        session['email'] = user_data["email"]  # ✅ Add this line
        session['document'] = user_data.get("document", "")  # ✅ Optional: for home.html
        session['status'] = user_data.get("status", "pending")

        flash('Login successful!')
        write_secure_log("User Login", username, "Success")
        return redirect(url_for('profile_bp.profile')) 

    return render_template('login.html')
@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash("Unauthorized access to password reset.", "danger")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['password']

        # Validate OTP and expiration
        if otp != session.get('reset_otp') or time.time() - session.get('otp_timestamp', 0) > 300:
            flash("Invalid or expired OTP.")
            return redirect(url_for('auth.forgot_password'))

        email = session.get('reset_email')
        if not email:
            flash("Session expired. Please try again.", "danger")
            return redirect(url_for('auth.forgot_password'))

        password_error = validate_password(new_password)
        if password_error:
            flash(password_error, 'danger')
            return redirect(url_for('auth.reset_password'))

        user = mongo.db.users.find_one({"email": email})
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('auth.forgot_password'))

        # Decrypt old private key using old password-derived AES key (optional)
        try:
            encrypted_private_key = user['encrypted_private_key']
            salt = base64.b64decode(encrypted_private_key['salt'])
            nonce = base64.b64decode(encrypted_private_key['nonce'])
            tag = base64.b64decode(encrypted_private_key['tag'])
            ciphertext = base64.b64decode(encrypted_private_key['ciphertext'])

            # Derive old AES key from previous password
            # This assumes you collect or store the old password temporarily
            old_password = "user's old password"  # You don’t have this after OTP flow
            old_aes_key = PBKDF2(old_password, salt, dkLen=32, count=100000)
            cipher = AES.new(old_aes_key, AES.MODE_EAX, nonce=nonce)
            private_key = cipher.decrypt_and_verify(ciphertext, tag)

        except Exception:
            # Fallback: generate a new private key instead
            rsa_key = RSA.generate(2048)
            private_key = rsa_key.export_key()
            public_key = rsa_key.publickey().export_key()

        # Encrypt private key with new password
        new_salt = os.urandom(16)
        new_aes_key = PBKDF2(new_password, new_salt, dkLen=32, count=100000)
        cipher = AES.new(new_aes_key, AES.MODE_EAX)
        new_ciphertext, new_tag = cipher.encrypt_and_digest(private_key)

        new_encrypted_private_key = {
            "salt": base64.b64encode(new_salt).decode(),
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "ciphertext": base64.b64encode(new_ciphertext).decode(),
            "tag": base64.b64encode(new_tag).decode()
        }

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Update user password + encrypted private key (and public key if regenerated)
        update_data = {
            "password": hashed_password,
            "encrypted_private_key": new_encrypted_private_key
        }

        if "public_key" not in user:  # if fallback was used
            update_data["public_key"] = public_key.decode()

        result = mongo.db.users.update_one({"email": email}, {"$set": update_data})

        # Cleanup session
        session.pop('reset_otp', None)
        session.pop('reset_email', None)
        session.pop('otp_timestamp', None)

        flash("Password reset successfully.", "success")
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html')

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = mongo.db.users.find_one({"username": username})

        # Rate limiting: Max 3 OTPs per 5 mins
        now = time.time()
        attempts = session.get("otp_attempts", [])
        attempts = [t for t in attempts if now - t < 300]
        if len(attempts) >= 3:
            flash("Too many OTP requests. Please wait before trying again.", "warning")
            return redirect(url_for('auth.forgot_password'))
        session['otp_attempts'] = attempts + [now]

        if user:
            email = user.get("email")
            otp = generate_otp()
            session['reset_email'] = email
            session['reset_otp'] = otp
            session['otp_timestamp'] = now

            msg = Message(
                subject="Your OTP to Reset Password",
                sender=os.getenv("MAIL_USERNAME"),
                recipients=[email]
            )
            msg.body = f"""Hi {username},

Your OTP to reset your password is: {otp}

It will expire in 5 minutes.

If this wasn't you, please ignore this email.
"""
            try:
                mail.send(msg)
                flash("If this username is registered, an OTP has been sent to the associated email.", "info")
                write_secure_log("OTP Sent", username, "Success")
            except Exception as e:
                flash("There was an error sending the OTP. Please try again later.", "danger")
                write_secure_log("OTP Email Failed", username, f"Error: {str(e)}")
        else:
            flash("If this username is registered, an OTP has been sent.", "info")
            write_secure_log("OTP Request", username, "Failed - User not found")

        return redirect(url_for('auth.reset_password'))

    return render_template('forgot_password.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('auth.login'))
@auth_bp.context_processor
def inject_notification_count():
    if 'user_id' in session:
        count = mongo.db.notifications.count_documents({
            "user_id": ObjectId(session['user_id']),
            "is_read": False
        })
        session['notification_count'] = count
    else:
        session['notification_count'] = 0
    return dict()

