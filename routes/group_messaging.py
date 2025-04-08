<<<<<<< Updated upstream
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
=======
# from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app, Response
# from bson.objectid import ObjectId
# from datetime import datetime
# from extensions import mongo
# from Crypto.Cipher import AES
# import base64
# from blockchain import SimpleBlockchain
# from werkzeug.utils import secure_filename
# from gridfs import GridFS

# ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# group_messaging_bp = Blueprint('group_messaging', __name__)

# # Initialize Blockchain for group messages
# group_blockchain = SimpleBlockchain()

# # ===== AES-192 Encryption Functions for Group Messages =====
# def get_aes_key():
#     encryption_key = current_app.config.get('ENCRYPTION_KEY')
#     if isinstance(encryption_key, str):
#         encryption_key = encryption_key.encode()
#     if len(encryption_key) != 24:
#         raise ValueError("ENCRYPTION_KEY must be exactly 24 bytes (192 bits) for AES-192")
#     return encryption_key

# def encrypt_message(message):
#     key = get_aes_key()
#     cipher = AES.new(key, AES.MODE_EAX)
#     ciphertext, tag = cipher.encrypt_and_digest(message.encode())
#     encrypted_data = {
#         "nonce": base64.b64encode(cipher.nonce).decode(),
#         "ciphertext": base64.b64encode(ciphertext).decode(),
#         "tag": base64.b64encode(tag).decode()
#     }
#     return encrypted_data

# def decrypt_message(encrypted_data):
#     key = get_aes_key()
#     try:
#         nonce = base64.b64decode(encrypted_data["nonce"])
#         ciphertext = base64.b64decode(encrypted_data["ciphertext"])
#         tag = base64.b64decode(encrypted_data["tag"])
#         cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
#         decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
#         return decrypted_message.decode()
#     except Exception:
#         return "Decryption failed"

# # ===== New Functions for Media Encryption =====
# def encrypt_media(media_bytes):
#     """
#     Encrypt media using the shared AES key in EAX mode.
#     Returns a dict with base64-encoded nonce, ciphertext, and tag.
#     """
#     key = get_aes_key()
#     cipher = AES.new(key, AES.MODE_EAX)
#     ciphertext, tag = cipher.encrypt_and_digest(media_bytes)
#     encrypted_data = {
#         "nonce": base64.b64encode(cipher.nonce).decode(),
#         "ciphertext": base64.b64encode(ciphertext).decode(),
#         "tag": base64.b64encode(tag).decode()
#     }
#     return encrypted_data

# def decrypt_media(encrypted_bytes, nonce_b64, tag_b64):
#     """
#     Decrypt media using the shared AES key in EAX mode.
#     """
#     key = get_aes_key()
#     nonce = base64.b64decode(nonce_b64)
#     tag = base64.b64decode(tag_b64)
#     cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
#     decrypted_media = cipher.decrypt_and_verify(encrypted_bytes, tag)
#     return decrypted_media

# @group_messaging_bp.route('/group_messages', methods=['GET', 'POST'])
# def group_messages():
#     if 'user_id' not in session:
#         flash('Please log in first.')
#         return redirect(url_for('auth.login'))

#     user_id = str(session['user_id'])
#     user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

#     if request.method == 'POST':
#         group_name = request.form.get('group_name')
#         message_text = request.form.get('message')

#         group = mongo.db.groups.find_one({'name': group_name})
#         if not group:
#             flash('Group not found.')
#             return redirect(url_for('group_messaging.group_messages'))

#         encrypted_message = encrypt_message(message_text)
#         sender_username = user['username']

#         # Store message hash in blockchain
#         group_blockchain.add_message(message_text, sender_username, group_name)

#         # Handle media file upload (only if user is approved)
#         media_file = request.files.get('media')
#         media_file_id = None
#         media_type = None
#         if user.get("status") == "approved":
#             if media_file and media_file.filename != "" and allowed_file(media_file.filename):
#                 filename = secure_filename(media_file.filename)
#                 fs = GridFS(mongo.db)
#                 media_bytes = media_file.read()
#                 # Encrypt media using the shared group AES key
#                 encrypted_media = encrypt_media(media_bytes)
#                 # Store the encrypted media's ciphertext as file content, and save the nonce and tag in metadata
#                 media_file_id = fs.put(
#                     base64.b64decode(encrypted_media["ciphertext"]),
#                     filename=filename,
#                     content_type=media_file.content_type,
#                     metadata={
#                         "nonce": encrypted_media["nonce"],
#                         "tag": encrypted_media["tag"]
#                     }
#                 )
#                 media_type = media_file.content_type
#         else:
#             if media_file and media_file.filename != "":
#                 flash("You are not approved to send media. Your text message has been sent without media.", "warning")

#         message_data = {
#             'sender_id': user_id,
#             'group_id': str(group['_id']),
#             'message': encrypted_message,
#             'timestamp': datetime.utcnow(),
#             'media_file': str(media_file_id) if media_file_id else None,
#             'media_type': media_type
#         }

#         mongo.db.group_messages.insert_one(message_data)
#         for member_id in group['members']:
#             if str(member_id) != user_id:
#                 mongo.db.notifications.insert_one({
#                     "user_id": ObjectId(member_id),
#                     "type": "group_message",
#                     "message": f"New message from {user['username']} in group '{group_name}'",
#                     "timestamp": datetime.utcnow(),
#                     "is_read": False,
#                     "link": "/group_messages"
#                 })

#         flash('Message sent to the group and stored in blockchain!')
#         return redirect(url_for('group_messaging.group_messages'))

#     # --- Only fetch messages from groups where the user is a member ---
#     user_groups = list(
#         mongo.db.groups.find(
#             {"members": {"$in": [ObjectId(user_id)]}}, 
#             {"_id": 1, "name": 1}
#         )
#     )

#     group_ids = [str(group["_id"]) for group in user_groups]
#     group_messages_cursor = mongo.db.group_messages.find({"group_id": {"$in": group_ids}}).sort("timestamp", -1)
#     # ------------------------------------------------------------------------

#     messages_list = []
#     for msg in group_messages_cursor:
#         sender = mongo.db.users.find_one({'_id': ObjectId(msg['sender_id'])})
#         group_obj = mongo.db.groups.find_one({'_id': ObjectId(msg['group_id'])})
#         sender_username = sender['username'] if sender else "Unknown"
#         group_name = group_obj['name'] if group_obj else "Unknown"
#         decrypted_message = decrypt_message(msg['message'])
#         messages_list.append({
#             'sender_username': sender_username,
#             'group_name': group_name,
#             'message': decrypted_message,
#             'timestamp': msg.get('timestamp', 'Unknown Time'),
#             'hash': msg['message'].get('ciphertext', ''),
#             'media_file': msg.get('media_file'),
#             'media_type': msg.get('media_type')
#         })

#     return render_template('group_messaging.html', messages=messages_list, groups=user_groups)

# @group_messaging_bp.route('/group_chain', methods=['GET'])
# def group_chain():
#     return jsonify({"chain": group_blockchain.get_chain()}), 200
# @group_messaging_bp.route('/create_group', methods=['GET', 'POST'])
# def create_group():
#     if 'user_id' not in session:
#         flash('Please log in first.')
#         return redirect(url_for('auth.login'))

#     current_user_id = ObjectId(session['user_id'])
#     user = mongo.db.users.find_one({'_id': current_user_id})

#     if user.get("status") != "approved":
#         flash("You are not approved to create groups or view all users.", "warning")
#         return redirect(url_for('group_messaging.group_messages'))

#     if request.method == 'POST':
#         group_name = request.form.get('group_name')
#         members = request.form.getlist('members')  # usernames from form

#         existing_group = mongo.db.groups.find_one({'name': group_name})
#         if existing_group:
#             flash('Group name already exists! Choose another name.')
#             return redirect(url_for('group_messaging.create_group'))

#         member_ids = []
#         for username in members:
#             user_obj = mongo.db.users.find_one({'username': username})  # ✅ removed 'status' filter
#             if user_obj:
#                 member_ids.append(user_obj['_id'])
#                 # Optional: notify if user isn't approved
#                 if user_obj.get("status") != "approved":
#                     flash(f"Note: '{username}' is not approved.", "warning")

#         # Add the current user (creator) to the group
#         if current_user_id not in member_ids:
#             member_ids.append(current_user_id)

#         if not member_ids:
#             flash('No valid users found for the group!')
#             return redirect(url_for('group_messaging.create_group'))

#         group_data = {
#             'name': group_name,
#             'members': member_ids,
#             'created_at': datetime.utcnow()
#         }

#         mongo.db.groups.insert_one(group_data)
#         flash(f'Group "{group_name}" created successfully!')
#         return redirect(url_for('group_messaging.group_messages'))

#     # ✅ Fetch all users except the current one (no status filter)
#     users = mongo.db.users.find(
#         {"_id": {"$ne": current_user_id}},
#         {"username": 1, "status": 1}  # Optional: include status for frontend
#     )

#     return render_template('create_group.html', users=users)

# @group_messaging_bp.route('/group_media/<file_id>', methods=['GET'])
# def serve_media(file_id):
#     fs = GridFS(mongo.db)
#     try:
#         file_doc = fs.get(ObjectId(file_id))
#     except Exception as e:
#         flash("File not found: " + str(e))
#         return redirect(url_for('group_messaging.group_messages'))
    
#     metadata = file_doc.metadata
#     # Decrypt the media using the shared AES key
#     key = get_aes_key()
#     nonce = base64.b64decode(metadata.get("nonce"))
#     tag = base64.b64decode(metadata.get("tag"))
#     cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
#     try:
#         decrypted_media = cipher.decrypt_and_verify(file_doc.read(), tag)
#     except Exception as e:
#         flash("Media decryption failed: " + str(e))
#         return redirect(url_for('group_messaging.group_messages'))
    
#     return Response(decrypted_media, mimetype=file_doc.content_type)
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app, Response
>>>>>>> Stashed changes
from bson.objectid import ObjectId
from datetime import datetime
from extensions import mongo
from Crypto.Cipher import AES
import base64
from blockchain import SimpleBlockchain
from werkzeug.utils import secure_filename
from gridfs import GridFS

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

group_messaging_bp = Blueprint('group_messaging', __name__)

# Initialize Blockchain for group messages
group_blockchain = SimpleBlockchain()

# AES-192 Encryption Functions
def get_aes_key():
    encryption_key = current_app.config.get('ENCRYPTION_KEY')
    if isinstance(encryption_key, str):
        encryption_key = encryption_key.encode()
    if len(encryption_key) != 24:
        raise ValueError("ENCRYPTION_KEY must be exactly 24 bytes (192 bits) for AES-192")
    return encryption_key

def encrypt_message(message):
    key = get_aes_key()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    encrypted_data = {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }
    return encrypted_data

def decrypt_message(encrypted_data):
    key = get_aes_key()
    try:
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        tag = base64.b64decode(encrypted_data["tag"])
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_message.decode()
    except Exception:
        return "Decryption failed"

<<<<<<< Updated upstream
=======
# ===== New Functions for Media Encryption =====
def encrypt_media(media_bytes):
    key = get_aes_key()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(media_bytes)
    encrypted_data = {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }
    return encrypted_data

def decrypt_media(encrypted_bytes, nonce_b64, tag_b64):
    key = get_aes_key()
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_media = cipher.decrypt_and_verify(encrypted_bytes, tag)
    return decrypted_media

# ----- Group Messages Route -----
>>>>>>> Stashed changes
@group_messaging_bp.route('/group_messages', methods=['GET', 'POST'])
def group_messages():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
        
    current_user_id = str(session['user_id'])
    user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})

    if request.method == 'POST':
        group_name = request.form.get('group_name')
        message_text = request.form.get('message')
        
        group = mongo.db.groups.find_one({'name': group_name})
        if not group:
            flash('Group not found.')
            return redirect(url_for('group_messaging.group_messages'))
        
        # ---- Prevent sending if any group member has a block relation with the sender ----
        for member_id in group.get('members', []):
            if str(member_id) != current_user_id:
                other = mongo.db.users.find_one({'_id': member_id})
                if other:
                    if (current_user_id in other.get("blocked_users", [])) or (str(other['_id']) in user.get("blocked_users", [])):
                        flash("Cannot send group message because a block exists with one or more group members.")
                        return redirect(url_for('group_messaging.group_messages'))
        
        encrypted_message = encrypt_message(message_text)
        sender_username = user['username']
        group_blockchain.add_message(message_text, sender_username, group_name)
        
        # ---- Handle media file upload (if approved) ----
        media_file = request.files.get('media')
        media_file_id = None
        media_type = None
        if user.get("status") == "approved":
            if media_file and media_file.filename != "" and allowed_file(media_file.filename):
                filename = secure_filename(media_file.filename)
                fs = GridFS(mongo.db)
<<<<<<< Updated upstream
                media_file_id = fs.put(media_file.read(), filename=filename, content_type=media_file.content_type)
=======
                media_bytes = media_file.read()
                encrypted_media = encrypt_media(media_bytes)
                media_file_id = fs.put(
                    base64.b64decode(encrypted_media["ciphertext"]),
                    filename=filename,
                    content_type=media_file.content_type,
                    metadata={
                        "nonce": encrypted_media["nonce"],
                        "tag": encrypted_media["tag"]
                    }
                )
>>>>>>> Stashed changes
                media_type = media_file.content_type
        else:
            if media_file and media_file.filename != "":
                flash("You are not approved to send media. Your text message has been sent without media.", "warning")
        
        message_data = {
            'sender_id': current_user_id,
            'group_id': str(group['_id']),
            'message': encrypted_message,
            'timestamp': datetime.utcnow(),
            'media_file': str(media_file_id) if media_file_id else None,
            'media_type': media_type
        }
        
        mongo.db.group_messages.insert_one(message_data)
<<<<<<< Updated upstream
        flash('Message sent to the group and stored in blockchain!')
        return redirect(url_for('group_messaging.group_messages'))

    # --- NEW RESTRICTION: Only fetch messages from groups where the user is a member ---
    # Fetch groups where the user is a member (get both _id and name)
    user_groups = list(mongo.db.groups.find({"members": {"$in": [user_id]}}, {"_id": 1, "name": 1}))
    # Extract the group IDs as strings
=======
        for member_id in group['members']:
            if str(member_id) != current_user_id:
                mongo.db.notifications.insert_one({
                    "user_id": member_id,
                    "type": "group_message",
                    "message": f"New message from {user['username']} in group '{group_name}'",
                    "timestamp": datetime.utcnow(),
                    "is_read": False,
                    "link": "/group_messages"
                })
        
        flash('Message sent to the group and stored in blockchain!')
        return redirect(url_for('group_messaging.group_messages'))
    
    # ---- GET: Fetch only groups where the user is a member ----
    user_groups = list(
        mongo.db.groups.find(
            {"members": {"$in": [ObjectId(current_user_id)]}}, 
            {"_id": 1, "name": 1}
        )
    )
>>>>>>> Stashed changes
    group_ids = [str(group["_id"]) for group in user_groups]
    # Only fetch messages from these groups
    group_messages_cursor = mongo.db.group_messages.find({"group_id": {"$in": group_ids}}).sort("timestamp", -1)
<<<<<<< Updated upstream
    # --------------------------------------------------------------------------

=======
    
>>>>>>> Stashed changes
    messages_list = []
    # ---- Filter out messages from blocked users for the current user ----
    for msg in group_messages_cursor:
        sender = mongo.db.users.find_one({'_id': ObjectId(msg['sender_id'])})
        group_obj = mongo.db.groups.find_one({'_id': ObjectId(msg['group_id'])})
        if sender:
            sender_id_str = str(sender['_id'])
            # Skip message if a block exists between the sender and current user
            if (sender_id_str in user.get("blocked_users", [])) or (current_user_id in sender.get("blocked_users", [])):
                continue
            sender_username = sender['username']
        else:
            sender_username = "Unknown"
        group_name = group_obj['name'] if group_obj else "Unknown"
        decrypted_message = decrypt_message(msg['message'])
        messages_list.append({
            'sender_username': sender_username,
            'group_name': group_name,
            'message': decrypted_message,
            'timestamp': msg.get('timestamp', 'Unknown Time'),
            'hash': msg['message'].get('ciphertext', ''),
            'media_file': msg.get('media_file'),
            'media_type': msg.get('media_type')
        })
    
    return render_template('group_messaging.html', messages=messages_list, groups=user_groups)

# ----- Group Chain Route -----
@group_messaging_bp.route('/group_chain', methods=['GET'])
def group_chain():
    return jsonify({"chain": group_blockchain.get_chain()}), 200

<<<<<<< Updated upstream
=======
# ----- Modified Create Group Route -----
>>>>>>> Stashed changes
@group_messaging_bp.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
<<<<<<< Updated upstream
        
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    # Only approved users can create groups or view the list of users
    if user.get("status") != "approved":
        flash("You are not approved to create groups or view all users.", "warning")
=======
    
    current_user_id = ObjectId(session['user_id'])
    current_user = mongo.db.users.find_one({'_id': current_user_id})
    
    if current_user.get("status") != "approved":
        flash("You are not approved to create groups.", "warning")
>>>>>>> Stashed changes
        return redirect(url_for('group_messaging.group_messages'))
    
    if request.method == 'POST':
        group_name = request.form.get('group_name')
<<<<<<< Updated upstream
        members = request.form.getlist('members')  # List of usernames

=======
        members = request.form.getlist('members')  # list of usernames from form
        
>>>>>>> Stashed changes
        existing_group = mongo.db.groups.find_one({'name': group_name})
        if existing_group:
            flash('Group name already exists! Choose another name.')
            return redirect(url_for('group_messaging.create_group'))
        
        member_ids = []
        for username in members:
<<<<<<< Updated upstream
            user_obj = mongo.db.users.find_one({'username': username, 'status': 'approved'})
            if user_obj:
                member_ids.append(str(user_obj['_id']))

=======
            user_obj = mongo.db.users.find_one({'username': username})
            if user_obj:
                # Prevent adding if there is any block relation between current user and candidate
                if (str(user_obj['_id']) in current_user.get("blocked_users", [])) or (str(current_user_id) in user_obj.get("blocked_users", [])):
                    flash(f"Cannot add {username} to group due to block restrictions.", "danger")
                    return redirect(url_for('group_messaging.create_group'))
                member_ids.append(user_obj['_id'])
        
        # Add the current user (creator) if not already in the list
        if current_user_id not in member_ids:
            member_ids.append(current_user_id)
        
>>>>>>> Stashed changes
        if not member_ids:
            flash('No valid approved users found for the group!')
            return redirect(url_for('group_messaging.create_group'))
        
        group_data = {
            'name': group_name,
            'members': member_ids,
            'created_at': datetime.utcnow()
        }
        
        mongo.db.groups.insert_one(group_data)
        flash(f'Group "{group_name}" created successfully!')
        return redirect(url_for('group_messaging.group_messages'))
<<<<<<< Updated upstream

    # Only list approved users in the create group page
    users = mongo.db.users.find({"status": "approved"}, {"username": 1})
    return render_template('create_group.html', users=users)
=======
    
    # GET: Fetch all eligible users (exclude current user and any with block relation)
    all_users = list(mongo.db.users.find(
        {"_id": {"$ne": current_user_id}},
        {"username": 1, "status": 1}
    ))
    eligible_users = []
    for user in all_users:
        if (str(user['_id']) not in current_user.get("blocked_users", [])) and (str(current_user_id) not in user.get("blocked_users", [])):
            eligible_users.append(user)
    
    return render_template('create_group.html', users=eligible_users)

@group_messaging_bp.route('/group_media/<file_id>', methods=['GET'])
def serve_media(file_id):
    fs = GridFS(mongo.db)
    try:
        file_doc = fs.get(ObjectId(file_id))
    except Exception as e:
        flash("File not found: " + str(e))
        return redirect(url_for('group_messaging.group_messages'))
    
    metadata = file_doc.metadata
    key = get_aes_key()
    nonce = base64.b64decode(metadata.get("nonce"))
    tag = base64.b64decode(metadata.get("tag"))
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        decrypted_media = cipher.decrypt_and_verify(file_doc.read(), tag)
    except Exception as e:
        flash("Media decryption failed: " + str(e))
        return redirect(url_for('group_messaging.group_messages'))
    
    return Response(decrypted_media, mimetype=file_doc.content_type)
>>>>>>> Stashed changes
