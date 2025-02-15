from flask import Flask
from pymongo import MongoClient
from backend import models

app = Flask(__name__)
mongo = MongoClient("mongodb+srv://pranav22363:m6UrGZqKnMlcpARb@cluster0.5uvzn.mongodb.net/")
db = mongo["App"]  

@app.route('/')
def homePage():
    return "Home Page"

@app.route('/addUser')
def addUser():
    userAccounts = db["UserAccounts"] 
    userAccounts.create_index("username", unique=True)
    
    newUser = models.User(username = "Pranav", password = "1234")
    try:
        userAccounts.insert_one({"username" : newUser.username, "password" : newUser.password})
        return "User Added"
    except:
        return "User already exists"
    
if __name__ == "__main__":
    app.run(host = '0.0.0.0')
