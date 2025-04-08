from pymongo import MongoClient
from bson import ObjectId

# Connect to your MongoDB
client = MongoClient("mongodb://localhost:27017")
db = client.your_database_name  # Replace with your DB name

# Find the most recently inserted post
post = db.posts.find_one(sort=[("_id", -1)])  # Gets the newest post
print(post)