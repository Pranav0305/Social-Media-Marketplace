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

# New imports for RSA key generation and AES encryption for the private key
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import os
import base64

auth_bp = Blueprint('auth', __name__)

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

        # Generate password hash for authentication
        hashed_password = generate_password_hash(password)
        
        # Initialize GridFS instance
        fs = GridFS(mongo.db)
        document_id = None
        
        if document and allowed_file(document.filename):
            filename = secure_filename(document.filename)
            # Save the file to GridFS
            document_id = fs.put(document.read(), filename=filename, content_type=document.content_type)
            print("GridFS file stored with ID:", document_id)  # Debug log

        # ===== RSA Key Pair Generation for E2E Encryption =====
        # Generate a new RSA key pair (2048 bits)
        rsa_key = RSA.generate(2048)
        private_key = rsa_key.export_key()      # Private key (in bytes)
        public_key = rsa_key.publickey().export_key()  # Public key (in bytes)

        # Encrypt the private key with AES using a key derived from the user's password.
        # Generate a random salt
        salt = os.urandom(16)
        # Derive a 32-byte AES key using PBKDF2 (using the plain password, not the hash)
        aes_key = PBKDF2(password, salt, dkLen=32, count=100000)
        # Create an AES cipher in EAX mode
        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(private_key)
        # Store the encrypted private key along with salt, nonce, and tag (all base64 encoded)
        encrypted_private_key = {
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }
        # ======================================================

        user_data = {
            'email': email,
            'username': username,
            'password': hashed_password,
            'status': 'pending',  # Admin approval required for certain functionalities
            'profile': {'profile_picture': '', 'bio': ''},
            'document': str(document_id) if document_id else '',
            # Store the public key as a string for later use in encryption
            'public_key': public_key.decode(),
            # Store the encrypted private key (should be decrypted only after login)
            'encrypted_private_key': encrypted_private_key
        }

        mongo.db.users.insert_one(user_data)
        flash('Registration successful. Please wait for admin approval.', 'success')
        write_secure_log("User Registered", username, "Success")
        return redirect(url_for('auth.login'))

    return render_template('register.html')


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
        session['user_id'] = str(user_data["_id"])
        session['username'] = user_data["username"]
        session['status'] = user_data.get("status", "pending")  # e.g., 'approved' or 'pending'

        flash('Login successful!')
        write_secure_log("User Login", username, "Success")
        return redirect(url_for('profile_bp.profile')) 

    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('auth.login'))
