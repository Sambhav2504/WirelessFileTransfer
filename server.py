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

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024  # 150MB limit

# Store file access codes and keys
file_data = {}

# Error handler for large files
@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "File exceeds 150MB limit"}), 413

# Generate a 4-digit PIN
def generate_pin():
    return "".join(random.choices(string.digits, k=4))

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
            print(f"Cleanup error for {filename}: {str(e)}")

# Initialize cleanup
atexit.register(cleanup_old_files)
cleanup_old_files()

@app.route("/")
def upload_form():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
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
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

@app.route("/download", methods=["POST"])
def download_file():
    code = request.form.get("code", "").strip()
    key = request.form.get("key", "").strip()

    if not code or not key:
        return render_template("index.html", error="Both code and key are required")

    if code not in file_data:
        return render_template("index.html", error="Invalid access code")

    if key != file_data[code]["key"]:
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
    app.run(host="0.0.0.0", port=5000, debug=False)  # debug=False for production
