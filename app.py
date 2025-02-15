from flask import Flask, request, render_template, jsonify
from pymongo import MongoClient
from backend import models

app = Flask(__name__)
mongo = MongoClient("mongodb+srv://pranav22363:m6UrGZqKnMlcpARb@cluster0.5uvzn.mongodb.net/")
db = mongo["App"]  

@app.route('/', methods = ['GET', 'POST'])
def loginPage():
    userAccounts = db['UserAccounts']
    
    if request.method == 'POST':
        uName = request.form.get("username")
        pwd = request.form.get("pwd")
        if uName and pwd:
            currUser = userAccounts.find({"username" : uName, "password" : pwd})
            try:
                currUserEntry = next(currUser, None)
                print(currUserEntry)
            except:
                print(currUser)
    return render_template("loginPage.html")

@app.route('/registerUser', methods = ['GET', 'POST'])
def registerUser():
    userAccounts = db["UserAccounts"]
    
    if request.method == 'POST':
        uName = request.form.get("username")
        pwd = request.form.get("pwd")
        
        if uName and pwd:
            newUser = models.User(username = uName, password = pwd)
            try:
                userAccounts.insert_one({"username" : newUser.username, "password" : newUser.password})
                return "User Added"
            except:
                return "User already exists"
            
    return render_template("registerUserPage.html")


@app.route('/users', methods=['GET'])
def get_registered_users():
    userAccounts = db["UserAccounts"]
    
    try:
        users = userAccounts.find({}, {"_id": 0, "username": 1})  
        return jsonify(list(users))

    except Exception as e:
        return jsonify({"error": str(e)})
  
if __name__ == "__main__":
    app.run(host = '0.0.0.0')
