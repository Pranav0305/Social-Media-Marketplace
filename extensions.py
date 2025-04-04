from flask_pymongo import PyMongo
from flask_login import LoginManager
login_manager = LoginManager()


mongo = PyMongo()  
from flask_mail import Mail

mail = Mail()
