from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
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

@group_messaging_bp.route('/group_messages', methods=['GET', 'POST'])
def group_messages():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))

    user_id = str(session['user_id'])
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

    if request.method == 'POST':
        group_name = request.form.get('group_name')
        message_text = request.form.get('message')

        group = mongo.db.groups.find_one({'name': group_name})
        if not group:
            flash('Group not found.')
            return redirect(url_for('group_messaging.group_messages'))

        encrypted_message = encrypt_message(message_text)
        sender_username = user['username']

        # Store message hash in blockchain
        group_blockchain.add_message(message_text, sender_username, group_name)

        # Handle media file upload (only if user is approved)
        media_file = request.files.get('media')
        media_file_id = None
        media_type = None
        if user.get("status") == "approved":
            if media_file and media_file.filename != "" and allowed_file(media_file.filename):
                filename = secure_filename(media_file.filename)
                fs = GridFS(mongo.db)
                media_file_id = fs.put(media_file.read(), filename=filename, content_type=media_file.content_type)
                media_type = media_file.content_type
        else:
            if media_file and media_file.filename != "":
                flash("You are not approved to send media. Your text message has been sent without media.", "warning")

        message_data = {
            'sender_id': user_id,
            'group_id': str(group['_id']),
            'message': encrypted_message,
            'timestamp': datetime.utcnow(),
            'media_file': str(media_file_id) if media_file_id else None,
            'media_type': media_type
        }

        mongo.db.group_messages.insert_one(message_data)
        flash('Message sent to the group and stored in blockchain!')
        return redirect(url_for('group_messaging.group_messages'))

    # --- NEW RESTRICTION: Only fetch messages from groups where the user is a member ---
    # Fetch groups where the user is a member (get both _id and name)
    user_groups = list(mongo.db.groups.find({"members": {"$in": [user_id]}}, {"_id": 1, "name": 1}))
    # Extract the group IDs as strings
    group_ids = [str(group["_id"]) for group in user_groups]
    # Only fetch messages from these groups
    group_messages_cursor = mongo.db.group_messages.find({"group_id": {"$in": group_ids}}).sort("timestamp", -1)
    # --------------------------------------------------------------------------

    messages_list = []
    for msg in group_messages_cursor:
        sender = mongo.db.users.find_one({'_id': ObjectId(msg['sender_id'])})
        group_obj = mongo.db.groups.find_one({'_id': ObjectId(msg['group_id'])})
        sender_username = sender['username'] if sender else "Unknown"
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

@group_messaging_bp.route('/group_chain', methods=['GET'])
def group_chain():
    return jsonify({"chain": group_blockchain.get_chain()}), 200

@group_messaging_bp.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
        
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    # Only approved users can create groups or view the list of users
    if user.get("status") != "approved":
        flash("You are not approved to create groups or view all users.", "warning")
        return redirect(url_for('group_messaging.group_messages'))

    if request.method == 'POST':
        group_name = request.form.get('group_name')
        members = request.form.getlist('members')  # List of usernames

        existing_group = mongo.db.groups.find_one({'name': group_name})
        if existing_group:
            flash('Group name already exists! Choose another name.')
            return redirect(url_for('group_messaging.create_group'))

        member_ids = []
        for username in members:
            user_obj = mongo.db.users.find_one({'username': username, 'status': 'approved'})
            if user_obj:
                member_ids.append(str(user_obj['_id']))

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

    # Only list approved users in the create group page
    users = mongo.db.users.find({"status": "approved"}, {"username": 1})
    return render_template('create_group.html', users=users)
