from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, jsonify
from bson.objectid import ObjectId
from datetime import datetime
from extensions import mongo
from Crypto.Cipher import AES 
import base64
import time
from blockchain import SimpleBlockchain 
from werkzeug.utils import secure_filename
from gridfs import GridFS

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

messaging_bp = Blueprint('messaging', __name__)

blockchain = SimpleBlockchain()

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

@messaging_bp.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

    if request.method == 'POST':
        recipient_username = request.form.get('recipient')
        message_text = request.form.get('message')

        recipient = mongo.db.users.find_one({'username': recipient_username})
        if not recipient:
            flash('Recipient not found.')
            return redirect(url_for('messaging.messages'))

        # Encrypt the message text
        encrypted_message = encrypt_message(message_text)

        # Store message hash in the blockchain
        sender_username = user['username']
        blockchain.add_message(message_text, sender_username, recipient_username)

        # Handle media file upload (only if the user is approved)
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

        # Store encrypted message with optional media info in MongoDB
        message_data = {
            'sender_id': user_id,
            'recipient_id': str(recipient['_id']),
            'message': encrypted_message,
            'timestamp': datetime.utcnow(),
            'media_file': str(media_file_id) if media_file_id else None,
            'media_type': media_type
        }

        mongo.db.messages.insert_one(message_data)
        flash('Message sent and stored in blockchain!')
        return redirect(url_for('messaging.messages'))

    messages_cursor = mongo.db.messages.find({
        '$or': [{'sender_id': user_id}, {'recipient_id': user_id}]
    }).sort("timestamp", -1)

    messages_list = []
    for msg in messages_cursor:
        sender = mongo.db.users.find_one({'_id': ObjectId(msg['sender_id'])})
        recipient = mongo.db.users.find_one({'_id': ObjectId(msg['recipient_id'])})
        sender_username = sender['username'] if sender else "Unknown"
        recipient_username = recipient['username'] if recipient else "Unknown"
        decrypted_message = decrypt_message(msg['message'])
        messages_list.append({
            'sender_username': sender_username,
            'recipient_username': recipient_username,
            'message': decrypted_message,
            'timestamp': msg.get('timestamp', 'Unknown Time'),
            'hash': msg['message'].get('ciphertext', ''),  # Using ciphertext as a reference
            'media_file': msg.get('media_file'),
            'media_type': msg.get('media_type')
        })

    return render_template('messaging.html', messages=messages_list)

@messaging_bp.route('/get_chain', methods=['GET'])
def get_chain():
    return jsonify({"chain": blockchain.get_chain()}), 200
