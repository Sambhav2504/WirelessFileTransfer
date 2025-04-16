from flask import Flask, request, render_template, send_file, jsonify
import os
import random
import string
import time
import threading
from datetime import datetime, timedelta
import atexit
import shutil
import hashlib
import base64
import requests
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from functools import wraps
import redis
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024  # 150MB limit

# Redis configuration for rate limiting and IP blocking
REDIS_ENABLED = os.environ.get('REDIS_ENABLED', 'false').lower() == 'true'
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)

# In-memory fallback for rate limiting when Redis is not available
rate_limit_data = {}
failed_attempts_data = {}
blocked_ips = {}

# Initialize Redis client with error handling
redis_client = None
if REDIS_ENABLED:
    try:
        redis_client = redis.Redis(
            host=REDIS_HOST, 
            port=REDIS_PORT, 
            password=REDIS_PASSWORD,
            socket_timeout=2,
            socket_connect_timeout=2,
            retry_on_timeout=True
        )
        # Test connection
        redis_client.ping()
        logger.info("Successfully connected to Redis")
    except Exception as e:
        logger.warning(f"Failed to connect to Redis: {str(e)}. Using in-memory fallback.")
        redis_client = None

RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds
MAX_REQUESTS = 100  # Maximum requests per hour
BLOCK_DURATION = 1800  # 30 minutes in seconds
MAX_FAILED_ATTEMPTS = 10  # Maximum failed attempts before blocking

# Store file access codes and keys
file_data = {}

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        key = f"rate_limit:{ip}"
        
        # Check if IP is blocked
        if redis_client and redis_client.get(f"blocked:{ip}"):
            return jsonify({"error": "Too many failed attempts. Please try again later."}), 429
        
        # Fallback to in-memory storage if Redis is not available
        if not redis_client:
            # Check if IP is blocked in memory
            if ip in blocked_ips and blocked_ips[ip] > datetime.now():
                return jsonify({"error": "Too many failed attempts. Please try again later."}), 429
            
            # Get current request count from memory
            if ip not in rate_limit_data:
                rate_limit_data[ip] = {
                    'count': 1,
                    'expires': datetime.now() + timedelta(seconds=RATE_LIMIT_WINDOW)
                }
            elif rate_limit_data[ip]['expires'] < datetime.now():
                rate_limit_data[ip] = {
                    'count': 1,
                    'expires': datetime.now() + timedelta(seconds=RATE_LIMIT_WINDOW)
                }
            elif rate_limit_data[ip]['count'] >= MAX_REQUESTS:
                return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
            else:
                rate_limit_data[ip]['count'] += 1
            
            return f(*args, **kwargs)
        
        # Redis is available, use it for rate limiting
        try:
            # Get current request count
            current = redis_client.get(key)
            if current is None:
                redis_client.setex(key, RATE_LIMIT_WINDOW, 1)
            elif int(current) >= MAX_REQUESTS:
                return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
            else:
                redis_client.incr(key)
        except Exception as e:
            logger.error(f"Redis error in rate_limit: {str(e)}")
            # Fall back to in-memory rate limiting
            if ip not in rate_limit_data:
                rate_limit_data[ip] = {
                    'count': 1,
                    'expires': datetime.now() + timedelta(seconds=RATE_LIMIT_WINDOW)
                }
            elif rate_limit_data[ip]['expires'] < datetime.now():
                rate_limit_data[ip] = {
                    'count': 1,
                    'expires': datetime.now() + timedelta(seconds=RATE_LIMIT_WINDOW)
                }
            elif rate_limit_data[ip]['count'] >= MAX_REQUESTS:
                return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
            else:
                rate_limit_data[ip]['count'] += 1
        
        return f(*args, **kwargs)
    return decorated_function

# Track failed attempts
def track_failed_attempt(ip):
    if not redis_client:
        # Fallback to in-memory storage
        if ip not in failed_attempts_data:
            failed_attempts_data[ip] = {
                'count': 1,
                'expires': datetime.now() + timedelta(seconds=BLOCK_DURATION)
            }
        elif failed_attempts_data[ip]['expires'] < datetime.now():
            failed_attempts_data[ip] = {
                'count': 1,
                'expires': datetime.now() + timedelta(seconds=BLOCK_DURATION)
            }
        else:
            failed_attempts_data[ip]['count'] += 1
        
        if failed_attempts_data[ip]['count'] >= MAX_FAILED_ATTEMPTS:
            blocked_ips[ip] = datetime.now() + timedelta(seconds=BLOCK_DURATION)
            return True
        return False
    
    # Redis is available
    try:
        key = f"failed_attempts:{ip}"
        attempts = redis_client.incr(key)
        redis_client.expire(key, BLOCK_DURATION)
        
        if attempts >= MAX_FAILED_ATTEMPTS:
            redis_client.setex(f"blocked:{ip}", BLOCK_DURATION, 1)
            return True
        return False
    except Exception as e:
        logger.error(f"Redis error in track_failed_attempt: {str(e)}")
        # Fall back to in-memory tracking
        if ip not in failed_attempts_data:
            failed_attempts_data[ip] = {
                'count': 1,
                'expires': datetime.now() + timedelta(seconds=BLOCK_DURATION)
            }
        elif failed_attempts_data[ip]['expires'] < datetime.now():
            failed_attempts_data[ip] = {
                'count': 1,
                'expires': datetime.now() + timedelta(seconds=BLOCK_DURATION)
            }
        else:
            failed_attempts_data[ip]['count'] += 1
        
        if failed_attempts_data[ip]['count'] >= MAX_FAILED_ATTEMPTS:
            blocked_ips[ip] = datetime.now() + timedelta(seconds=BLOCK_DURATION)
            return True
        return False

# Generate an alphanumeric 6-character code
def generate_pin():
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=6))

# Derive encryption key from PIN
def derive_key(pin):
    salt = b"unique_salt_value"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))

# Cleanup old files (24-hour retention)
def cleanup_old_files():
    now = datetime.now()
    for filename in os.listdir(UPLOAD_FOLDER):
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        try:
            if os.path.isfile(filepath):
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                if now - file_time > timedelta(hours=24):
                    os.remove(filepath)
                    for code in list(file_data.keys()):
                        if file_data[code]['path'] == filepath:
                            del file_data[code]
        except Exception as e:
            logger.error(f"Cleanup error for {filename}: {str(e)}")

# Initialize cleanup
atexit.register(cleanup_old_files)
cleanup_old_files()

@app.route("/")
def upload_form():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
@rate_limit
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file selected"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    try:
        access_code = generate_pin()
        decryption_key = generate_pin()
        
        file_data_bytes = file.read()
        file_size_mb = round(len(file_data_bytes) / (1024 * 1024), 2)
        
        derived_key = derive_key(decryption_key)
        cipher = Fernet(derived_key)
        encrypted_data = cipher.encrypt(file_data_bytes)

        filename = file.filename
        encrypted_file_path = os.path.join(UPLOAD_FOLDER, f"{filename}.enc")
        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_data)

        file_data[access_code] = {
            "path": encrypted_file_path,
            "key": decryption_key,
            "filename": filename,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "size_mb": file_size_mb
        }

        return jsonify({
            "success": True,
            "file": filename,
            "size_mb": file_size_mb,
            "code": access_code,
            "key": decryption_key,
            "warning": "Download immediately - files expire in 24 hours or if server restarts"
        })

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

@app.route("/download", methods=["POST"])
@rate_limit
def download_file():
    code = request.form.get("code", "").strip()
    key = request.form.get("key", "").strip()
    ip = request.remote_addr

    if not code or not key:
        return render_template("index.html", error="Both code and key are required")

    if code not in file_data:
        if track_failed_attempt(ip):
            return render_template("index.html", error="Too many failed attempts. Please try again later.")
        return render_template("index.html", error="Invalid access code")

    if key != file_data[code]["key"]:
        if track_failed_attempt(ip):
            return render_template("index.html", error="Too many failed attempts. Please try again later.")
        return render_template("index.html", error="Invalid decryption key")

    try:
        encrypted_file_path = file_data[code]["path"]
        if not os.path.exists(encrypted_file_path):
            return render_template("index.html", error="File expired or deleted")

        derived_key = derive_key(key)
        cipher = Fernet(derived_key)
        
        with open(encrypted_file_path, "rb") as f:
            decrypted_data = cipher.decrypt(f.read())

        temp_path = os.path.join(UPLOAD_FOLDER, file_data[code]["filename"])
        with open(temp_path, "wb") as f:
            f.write(decrypted_data)

        response = send_file(
            temp_path,
            as_attachment=True,
            download_name=file_data[code]["filename"]
        )
        
        @response.call_on_close
        def cleanup():
            try:
                os.remove(temp_path)
            except:
                pass
                
        return response

    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return render_template("index.html", error=f"Download failed: {str(e)}")

# Keep-Alive Function (Prevents Render Shutdown)
def keep_alive():
    while True:
        try:
            print("Sending keep-alive request...")
            requests.get("https://secure-file-transfer-0tal.onrender.com")
        except Exception as e:
            print(f"Keep-alive request failed: {e}")
        time.sleep(600)  # Wait 10 minutes before sending the next request

# Start Keep-Alive Thread
keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
keep_alive_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)  # debug=False for production
