import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "HelloWorld")
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/socialMediaDB")
    ENCRYPTION_KEY = bytes.fromhex("8af3d8a815a38098cfea538a94986ed6571c97a326997a84")
    DEBUG = True
