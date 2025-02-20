from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from bson.objectid import ObjectId
from extensions import mongo
from cryptography.fernet import Fernet

messaging_bp = Blueprint('messaging', __name__)

def get_fernet():
    encryption_key = current_app.config.get('ENCRYPTION_KEY')
    if isinstance(encryption_key, str):
        encryption_key = encryption_key.encode()  
    return Fernet(encryption_key)

@messaging_bp.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('auth.login'))
    
    fernet = get_fernet()
    
    if request.method == 'POST':
        recipient_username = request.form.get('recipient')
        message_text = request.form.get('message')
        
        recipient = mongo.db.users.find_one({'username': recipient_username})
        if not recipient:
            flash('Recipient not found.')
            return redirect(url_for('messaging.messages'))
            
        
        encrypted_message = fernet.encrypt(message_text.encode()).decode()
        
        message_data = {
            'sender_id': session['user_id'],
            'recipient_id': str(recipient['_id']),
            'message': encrypted_message,
            'timestamp': None  
        }
        
        mongo.db.messages.insert_one(message_data)
        flash('Message sent!')
        return redirect(url_for('messaging.messages'))
    
    
    user_id = session['user_id']
    messages_cursor = mongo.db.messages.find({
        '$or': [{'sender_id': user_id}, {'recipient_id': user_id}]
    })
    
    messages_list = []
    for msg in messages_cursor:
        
        sender = mongo.db.users.find_one({'_id': ObjectId(msg['sender_id'])})
        recipient = mongo.db.users.find_one({'_id': ObjectId(msg['recipient_id'])})
        sender_username = sender['username'] if sender else "Unknown"
        recipient_username = recipient['username'] if recipient else "Unknown"
        
        
        if msg['sender_id'] == user_id or msg['recipient_id'] == user_id:
            try:
                decrypted_message = fernet.decrypt(msg['message'].encode()).decode()
            except Exception:
                decrypted_message = "Decryption failed"
        else:
            decrypted_message = msg['message']  
        
        messages_list.append({
            'sender_username': sender_username,
            'recipient_username': recipient_username,
            'message': decrypted_message
        })
    
    return render_template('messaging.html', messages=messages_list)
