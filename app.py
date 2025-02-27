from flask import Flask
from config import Config
from extensions import mongo  

app = Flask(__name__)
app.config.from_object(Config)


mongo.init_app(app)


from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.profile import profile_bp
from routes.messaging import messaging_bp
from routes.home import home_bp

app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(profile_bp)
app.register_blueprint(messaging_bp)
app.register_blueprint(home_bp)

#not an actual route , this is just for testing if mongoDB is connected or not 
@app.route('/dbtest')
def dbtest():
    try:
        print("MONGO_URI:", app.config.get("MONGO_URI"))
        print("mongo instance:", mongo)
        print("mongo.db:", mongo.db)
        mongo.db.command("ping")
        return "Successfully connected to MongoDB!"
    except Exception as e:
        return f"Failed to connect to MongoDB: {str(e)}"
@app.route('/')
def home():
    return render_template('home.html', current_user=current_user)

if __name__ == '__main__':
    app.run(debug=True)
