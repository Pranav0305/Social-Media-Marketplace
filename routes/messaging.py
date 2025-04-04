from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, jsonify, Response
from bson.objectid import ObjectId
from datetime import datetime
from extensions import mongo
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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

# ===== RSA Encryption / Decryption Functions for E2E Encryption =====
def encrypt_message(message, public_key_str):
    recipient_key = RSA.import_key(public_key_str)
    cipher = PKCS1_OAEP.new(recipient_key)
    ciphertext = cipher.encrypt(message.encode())
    return base64.b64encode(ciphertext).decode()

def decrypt_message(encrypted_message, private_key_str):
    private_key = RSA.import_key(private_key_str)
    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(encrypted_message)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message.decode()
# =======================================================================

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

        encrypted_for_recipient = encrypt_message(message_text, recipient['public_key'])
        encrypted_for_sender = encrypt_message(message_text, user['public_key'])
        sender_username = user['username']
        blockchain.add_message(message_text, sender_username, recipient_username)

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
            'recipient_id': str(recipient['_id']),
            'message_recipient': encrypted_for_recipient,
            'message_sender': encrypted_for_sender,
            'timestamp': datetime.utcnow(),
            'media_file': str(media_file_id) if media_file_id else None,
            'media_type': media_type
        }

        mongo.db.messages.insert_one(message_data)

        # ✅ Insert notification for the recipient
        mongo.db.notifications.insert_one({
            "user_id": ObjectId(recipient['_id']),
            "type": "message",
            "message": f"New message from {sender_username}",
            "timestamp": datetime.utcnow(),
            "is_read": False,
            "link": url_for('messaging.messages')  # or use a custom link like f"/messages/{sender_id}"
        })

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
        
        if user_id == msg['recipient_id']:
            try:
                decrypted_message = decrypt_message(msg['message_recipient'], session['private_key'])
            except Exception:
                decrypted_message = "Decryption failed"
        elif user_id == msg['sender_id']:
            try:
                decrypted_message = decrypt_message(msg['message_sender'], session['private_key'])
            except Exception:
                decrypted_message = "Decryption failed"
        else:
            decrypted_message = "Not authorized to view"

        messages_list.append({
            'sender_username': sender_username,
            'recipient_username': recipient_username,
            'message': decrypted_message,
            'timestamp': msg.get('timestamp', 'Unknown Time'),
            'hash': msg['message_recipient'][:30] + "...",  
            'media_file': msg.get('media_file'),
            'media_type': msg.get('media_type')
        })

    return render_template('messaging.html', messages=messages_list)

@messaging_bp.route('/get_chain', methods=['GET'])
def get_chain():
    return jsonify({"chain": blockchain.get_chain()}), 200

# ===== Updated Route to Serve Media Files =====
@messaging_bp.route('/media/<file_id>', methods=['GET'])
def serve_media(file_id):
    fs = GridFS(mongo.db)
    try:
        # Convert the string file_id to an ObjectId before retrieval
        file_doc = fs.get(ObjectId(file_id))
    except Exception as e:
        flash("File not found: " + str(e))
        return redirect(url_for('messaging.messages'))
    
    return Response(file_doc.read(), mimetype=file_doc.content_type)
