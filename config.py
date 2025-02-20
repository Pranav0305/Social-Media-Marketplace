import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "HelloWorld"
    
    MONGO_URI = os.environ.get("MONGO_URI") or "mongodb+srv://voldie1803:XsQqf28OaueJY11v@cluster0.fud6f.mongodb.net/socialMediaDB?retryWrites=true&w=majority"
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY") or b"g8H2CMXcp92DfTNFKKi3IsL8o3SENR2OYnuG00yRBmU="

#username - voldie1803
#password - XsQqf28OaueJY11v