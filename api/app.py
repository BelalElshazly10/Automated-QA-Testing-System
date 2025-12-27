# api/app.py

from flask import Flask, request, jsonify
from functools import wraps

# Import modules
from modules.auth import secure_auth
from modules.auth.secure_auth import register, login, verify_token
from modules.validation.validation import validate_username, validate_email, validate_text
from modules.encryption.aes import encrypt, decrypt
from modules.logging.logger import log_info, log_security_event

app = Flask(__name__)


# ----------------------------------------------------------
# Security Headers
# ----------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ----------------------------------------------------------
# JWT Protection Decorator
# ----------------------------------------------------------
def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"error": "Missing token"}), 401

        try:
            payload = verify_token(token)
        except Exception:
            return jsonify({"error": "Invalid or expired token"}), 401

        return f(payload, *args, **kwargs)

    return wrapper


# ----------------------------------------------------------
# Register
# ----------------------------------------------------------
@app.route("/register", methods=["POST"])
def api_register():
    data = request.json

    username = data.get("username")
    password = data.get("password")

    if not validate_username(username):
        return jsonify({"error": "Invalid username"}), 400

    result = register(username, password)

    if result.success:
        log_info(f"User {username} registered.")
        return jsonify({"message": result.message}), 201

    return jsonify({"error": result.message}), 400

@app.route("/", methods=["GET"])
def index():
    return {"status": "API is running"}

# ----------------------------------------------------------
# Login
# ----------------------------------------------------------
@app.route("/login", methods=["POST"])
def api_login():
    data = request.json

    username = data.get("username")
    password = data.get("password")

    result = login(username, password)

    if result.success:
        log_security_event(f"User {username} logged in.")
        return jsonify({"token": result.token})

    log_security_event(f"Failed login attempt for {username}.")
    return jsonify({"error": result.message}), 401


# ----------------------------------------------------------
# Input Validation
# ----------------------------------------------------------
@app.route("/validate", methods=["POST"])
def api_validate():
    data = request.json

    text = data.get("text")

    if validate_text(text):
        return jsonify({"valid": True})
    else:
        return jsonify({"valid": False}), 400


# ----------------------------------------------------------
# Encrypt
# ----------------------------------------------------------
@app.route("/encrypt", methods=["POST"])
def api_encrypt():
    data = request.json
    text = data.get("text")

    cipher = encrypt(text)

    log_info("AES encryption performed.")

    return jsonify({"cipher": cipher})


# ----------------------------------------------------------
# Decrypt
# ----------------------------------------------------------
@app.route("/decrypt", methods=["POST"])
def api_decrypt():
    data = request.json
    cipher = data.get("cipher")

    try:
        plain = decrypt(cipher)
        return jsonify({"plain": plain})
    except Exception:
        return jsonify({"error": "Decryption failed"}), 400


# ----------------------------------------------------------
# Secure endpoint (JWT required)
# ----------------------------------------------------------
@app.route("/secure-data", methods=["GET"])
@token_required
def secure_data(payload):
    username = payload["sub"]

    log_info(f"Secure data accessed by {username}")

    return jsonify({
        "message": f"Hello {username}, this is protected data.",
        "role": payload["role"]
    })



@app.route("/api/verify_token", methods=["POST"])
def api_verify_token():
    data = request.json
    token = data.get("token")
    if not token:
        return jsonify({"valid": False, "message": "Token missing"}), 400

    try:
        payload = secure_auth.verify_token(token)
        return jsonify({"valid": True, "payload": payload})
    except Exception as e:
        return jsonify({"valid": False, "message": str(e)}), 401



# ----------------------------------------------------------
# Run server
# ----------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
