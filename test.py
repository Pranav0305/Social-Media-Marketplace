from extensions import mongo
from app import app
from bson import ObjectId

with app.app_context():
    # Find the most recent post where 'post_image' is binary (i.e., not a base64 string)
    faulty_post = mongo.db.posts.find_one(
        { "post_image": { "$type": "binData" } },
        sort=[('_id', -1)]  # newest first
    )

    if faulty_post:
        result = mongo.db.posts.delete_one({ "_id": faulty_post["_id"] })
        print(f"✅ Deleted post with _id: {faulty_post['_id']}")
    else:
        print("✅ No faulty post with binary image found.")
