from flask import Flask,  send_from_directory
from config import Config
from extensions import mongo, login_manager  
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.profile import profile_bp
from routes.messaging import messaging_bp
from routes.home import home_bp
from routes.p2p_marketplace import p2p_marketplace_bp
from routes.posting import posting_bp
from routes.commenting import comment_bp
from flask_login import UserMixin
from werkzeug.middleware.proxy_fix import ProxyFix
from routes import profile, search  
from bson.objectid import ObjectId  # new

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.register_blueprint(search.search_bp)

app.config.from_object(Config)
# Configure secure session cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,    # Cookie is only sent over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Cookie is not accessible via JavaScript
    SESSION_COOKIE_SAMESITE='Lax'  # Helps mitigate CSRF attacks
)

app.secret_key = "your_secret_key" 

# Set cache control headers after every request
@app.after_request
def set_cache_headers(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
    return response

from routes.group_messaging import group_messaging_bp
app.register_blueprint(group_messaging_bp)

mongo.init_app(app)
UPLOAD_FOLDER = 'static/uploads/'

@app.route('/uploads/<filename>')  
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

login_manager.init_app(app)  
login_manager.login_view = "auth.login"  

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.email = user_data["email"]

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None

app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(profile_bp, url_prefix='/profile')
app.register_blueprint(messaging_bp)
app.register_blueprint(home_bp)
app.register_blueprint(p2p_marketplace_bp)
app.register_blueprint(posting_bp)
app.register_blueprint(comment_bp)

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000, debug=False)

