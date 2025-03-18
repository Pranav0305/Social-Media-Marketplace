from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from bson.objectid import ObjectId
from datetime import datetime
from extensions import mongo
from Crypto.Cipher import AES
import base64
import os
from blockchain import SimpleBlockchain

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

    user_id = str(session['user_id'])  # Convert to string for MongoDB matching

    if request.method == 'POST':
        group_name = request.form.get('group_name')
        message_text = request.form.get('message')

        group = mongo.db.groups.find_one({'name': group_name})
        if not group:
            flash('Group not found.')
            return redirect(url_for('group_messaging.group_messages'))

        encrypted_message = encrypt_message(message_text)

        sender_username = mongo.db.users.find_one({'_id': ObjectId(user_id)})['username']

        # Store message hash in blockchain
        group_blockchain.add_message(message_text, sender_username, group_name)

        message_data = {
            'sender_id': user_id,
            'group_id': str(group['_id']),
            'message': encrypted_message,
            'timestamp': datetime.utcnow()
        }

        mongo.db.group_messages.insert_one(message_data)
        flash('Message sent to the group and stored in blockchain!')
        return redirect(url_for('group_messaging.group_messages'))

    # ✅ Fix: Ensure user_groups query correctly fetches only groups where the user is a member
    user_groups = list(mongo.db.groups.find({"members": {"$in": [user_id]}}, {"name": 1}))  # Get group names only

    group_messages_cursor = mongo.db.group_messages.find().sort("timestamp", -1)

    messages_list = []
    for msg in group_messages_cursor:
        sender = mongo.db.users.find_one({'_id': ObjectId(msg['sender_id'])})
        group = mongo.db.groups.find_one({'_id': ObjectId(msg['group_id'])})

        sender_username = sender['username'] if sender else "Unknown"
        group_name = group['name'] if group else "Unknown"

        decrypted_message = decrypt_message(msg['message'])

        messages_list.append({
            'sender_username': sender_username,
            'group_name': group_name,
            'message': decrypted_message,
            'timestamp': msg.get('timestamp', 'Unknown Time')
        })

    return render_template('group_messaging.html', messages=messages_list, groups=user_groups)

@group_messaging_bp.route('/group_chain', methods=['GET'])
def group_chain():
    return jsonify({"chain": group_blockchain.get_chain()}), 200

@group_messaging_bp.route('/create_group', methods=['GET', 'POST'])
def create_group():
    """Allow users to create a new group"""
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        group_name = request.form.get('group_name')
        members = request.form.getlist('members')  # List of usernames

        existing_group = mongo.db.groups.find_one({'name': group_name})
        if existing_group:
            flash('Group name already exists! Choose another name.')
            return redirect(url_for('group_messaging.create_group'))

        # Get user IDs from usernames
        member_ids = []
        for username in members:
            user = mongo.db.users.find_one({'username': username})
            if user:
                member_ids.append(str(user['_id']))

        if not member_ids:
            flash('No valid users found for the group!')
            return redirect(url_for('group_messaging.create_group'))

        group_data = {
            'name': group_name,
            'members': member_ids,
            'created_at': datetime.utcnow()
        }

        mongo.db.groups.insert_one(group_data)
        flash(f'Group "{group_name}" created successfully!')
        return redirect(url_for('group_messaging.group_messages'))

    users = mongo.db.users.find({}, {"username": 1})  # Fetch all usernames
    return render_template('create_group.html', users=users)
