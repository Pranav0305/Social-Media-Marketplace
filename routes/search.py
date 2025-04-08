# from flask import Blueprint, render_template, request
# from extensions import mongo
# from bson import ObjectId

# search_bp = Blueprint('search_bp', __name__)

# @search_bp.route('/search')
# def search_users():
#     query = request.args.get('query', '')
#     users = []

#     if query:
#         cursor = mongo.db.users.find({
#             "$or": [
#                 {"username": {"$regex": query, "$options": "i"}},
#                 {"email": {"$regex": query, "$options": "i"}},
#                 {"profile.bio": {"$regex": query, "$options": "i"}}
#             ]
#         })
#         users = list(cursor)  # ✅ Convert cursor to list

#     return render_template('search.html', query=query, users=users)


from flask import Blueprint, render_template, request, session
from extensions import mongo
from bson import ObjectId

search_bp = Blueprint('search_bp', __name__)

@search_bp.route('/search')
def search_users():
    query = request.args.get('query', '')
    users = []
    current_user_id = session.get('user_id')
    if query:
        cursor = mongo.db.users.find({
            "$or": [
                {"username": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}},
                {"profile.bio": {"$regex": query, "$options": "i"}}
            ]
        })
        for user in cursor:
            # If the profile owner has blocked the current user, skip the result.
            if current_user_id and (current_user_id in user.get("blocked_users", [])):
                continue
            users.append(user)
    return render_template('search.html', query=query, users=users)
