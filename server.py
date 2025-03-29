from flask import Flask, request, render_template, send_file, jsonify, redirect
import os
import random
import string
import time
from datetime import datetime, timedelta
import atexit
import shutil
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB file limit

# Store file access codes and keys
file_data = {}

# Generate a 4-digit PIN
def generate_pin():
    return "".join(random.choices(string.digits, k=4))

# Derive a strong encryption key from the PIN
def derive_key(pin):
    salt = b"unique_salt_value"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(pin.encode()))
    return key

# Cleanup old files (24-hour retention)
def cleanup_old_files():
    now = datetime.now()
    for filename in os.listdir(UPLOAD_FOLDER):
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.isfile(filepath):
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            if now - file_time > timedelta(hours=24):
                try:
                    os.remove(filepath)
                    # Also clean up file_data entries
                    for code in list(file_data.keys()):
                        if file_data[code]['path'] == filepath:
                            del file_data[code]
                except Exception as e:
                    print(f"Error deleting {filepath}: {e}")

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

    filename = file.filename
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    encrypted_file_path = file_path + ".enc"

    # Generate access credentials
    access_code = generate_pin()
    decryption_key = generate_pin()
    
    # Read and encrypt file
    file_data_bytes = file.read()
    file_size_kb = round(len(file_data_bytes) / 1024, 2)
    
    # Encrypt file
    derived_key = derive_key(decryption_key)
    cipher = Fernet(derived_key)
    encrypted_data = cipher.encrypt(file_data_bytes)

    # Save encrypted file
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)

    # Store file metadata
    file_data[access_code] = {
        "path": encrypted_file_path,
        "key": decryption_key,
        "filename": filename,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    return jsonify({
        "success": True,
        "file": filename,
        "size": file_size_kb,
        "timestamp": file_data[access_code]["timestamp"],
        "code": access_code,
        "key": decryption_key
    })

@app.route("/download", methods=["POST"])
def download_file():
    code = request.form.get("code", "").strip()
    key = request.form.get("key", "").strip()

    if not code or not key:
        return render_template("index.html", error="Both access code and decryption key are required")

    if code not in file_data:
        return render_template("index.html", error="Invalid access code")

    if key != file_data[code]["key"]:
        return render_template("index.html", error="Invalid decryption key")

    try:
        encrypted_file_path = file_data[code]["path"]
        if not os.path.exists(encrypted_file_path):
            return render_template("index.html", error="File has expired (24h retention)")

        original_filename = file_data[code]["filename"]
        decrypted_file_path = os.path.join(UPLOAD_FOLDER, original_filename)

        # Decrypt file
        derived_key = derive_key(key)
        cipher = Fernet(derived_key)
        
        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()
            
        decrypted_data = cipher.decrypt(encrypted_data)

        # Save temporarily for download
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        # Send file and then delete temporary decrypted version
        response = send_file(
            decrypted_file_path,
            as_attachment=True,
            download_name=original_filename
        )
        
        # Clean up decrypted file after sending
        @response.call_on_close
        def remove_file():
            try:
                os.remove(decrypted_file_path)
            except:
                pass
                
        return response
        
    except Exception as e:
        return render_template("index.html", error=f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)