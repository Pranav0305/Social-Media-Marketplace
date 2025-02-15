from flask import Flask, jsonify
from pymongo import MongoClient

app = Flask(__name__)
mongo = MongoClient("mongodb+srv://pranav22363:m6UrGZqKnMlcpARb@cluster0.5uvzn.mongodb.net/")
db = mongo["App"]
userAccounts = db["UserAccounts"]  
userAccounts.create_index("username", unique=True)

@app.route('/')
def homePage():
    return "Home Page"

@app.route('/addUser')
def addUser():
    newUser = {"username": "Pranav", "password": "1234"}
    
    try:
        userAccounts.insert_one(newUser)
        return "User Added"
    except:
        return "User already exists"

@app.route('/users', methods=['GET'])
def get_registered_users():
    try:
        users = userAccounts.find({}, {"_id": 0, "username": 1})  
        return jsonify(list(users))
    
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
