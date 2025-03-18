import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "HelloWorld"
    
    MONGO_URI = os.environ.get("MONGO_URI") or "mongodb+srv://voldie1803:XsQqf28OaueJY11v@cluster0.fud6f.mongodb.net/socialMediaDB?retryWrites=true&w=majority"
    ENCRYPTION_KEY = bytes.fromhex("8af3d8a815a38098cfea538a94986ed6571c97a326997a84")  
    DEBUG = False

#username - voldie1803
#password - XsQqf28OaueJY11v
