# import os
# from dotenv import load_dotenv
# load_dotenv()

# class Config:
#     SECRET_KEY = os.getenv("SECRET_KEY", "HelloWorld")
#     MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/socialMediaDB")
#     ENCRYPTION_KEY = bytes.fromhex("8af3d8a815a38098cfea538a94986ed6571c97a326997a84")
#     DEBUG = True
import os
import random
import string
from dotenv import load_dotenv
load_dotenv()

def generate_random_url(length=6):
    """Generate a random URL segment starting with a slash."""
    return "/" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "HelloWorld")
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/socialMediaDB")
    ENCRYPTION_KEY = bytes.fromhex("8af3d8a815a38098cfea538a94986ed6571c97a326997a84")
    DEBUG = True

    # Fixed admin URL provided via environment variable or defaulting to a predetermined value.
    ADMIN_URL = os.getenv("ADMIN_URL", "/c1r3a7d4b1e0f4c8a9b2d5e6f8a0c1e2f/admin")

    # URL mappings: admin is fixed, while others are random by default.
    RANDOM_URLS = {
        'admin': ADMIN_URL,
        'profile': os.getenv("PROFILE_URL", generate_random_url()),
        'auth': os.getenv("AUTH_URL", generate_random_url()),
        'messaging': os.getenv("MESSAGING_URL", generate_random_url()),
        'p2p_marketplace': os.getenv("P2P_MARKETPLACE_URL", generate_random_url()),
        'posting': os.getenv("POSTING_URL", generate_random_url()),
        'commenting': os.getenv("COMMENTING_URL", generate_random_url()),
        # Add additional mappings as needed.
    }
