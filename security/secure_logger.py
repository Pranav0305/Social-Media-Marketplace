import os
import time
import json
import hmac
import hashlib

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "secure_log.txt")
SECRET_KEY = b"305a3f92ebd1c8f55e47a98a9281a5ddd00073f88518fd21b89c59ae14c0005d"  
MAX_LOG_SIZE = 5000  
def compute_hmac(log_entry):
    return hmac.new(SECRET_KEY, log_entry.encode(), hashlib.sha256).hexdigest()

def write_secure_log(action, user_id, status):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    log_entry = {
        "timestamp": timestamp,
        "user_id": user_id,
        "action": action,
        "status": status
    }

    log_json = json.dumps(log_entry)
    log_hash = compute_hmac(log_json)

    with open(LOG_FILE, "a") as file:
        file.write(log_json + " | " + log_hash + "\n")

    rotate_logs()

def rotate_logs():
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
        os.rename(LOG_FILE, f"logs/secure_log_{int(time.time())}.txt")

def verify_logs():
    with open(LOG_FILE, "r") as file:
        for line in file:
            log_data, stored_hash = line.rsplit(" | ", 1)
            computed_hash = compute_hmac(log_data)
            if computed_hash.strip() != stored_hash.strip():
                print(f"[WARNING] Tampered Log Entry Detected: {log_data}")

if __name__ == "__main__":
    write_secure_log("User Login", "user123", "Success")
    write_secure_log("Admin Approval", "admin456", "User Approved")
    verify_logs()
