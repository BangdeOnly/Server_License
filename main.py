from flask import Flask, request, jsonify
from datetime import datetime
import json, os
from cryptography.fernet import Fernet

app = Flask(__name__)

# ---------------- CONFIG ----------------
# It's safer to set these as environment variables in Render.
# Defaults below are provided so the server runs out-of-the-box,
# but please set ADMIN_PASS and FERNET_KEY in Render's Environment settings.
ADMIN_PASS = os.environ.get("ADMIN_PASS", "DeAz1517")
FERNET_KEY = os.environ.get("FERNET_KEY", "qAz_Yf4PC3q-KZg6nnkoGnrVZg5qSRCEOD0MFYZmQNw=")
if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY environment variable not set. Generate one with Fernet.generate_key()")
fernet = Fernet(FERNET_KEY.encode())

DB_FILE = "license_db.enc"  # encrypted DB file (binary)

def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "rb") as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted.decode("utf-8"))
    except Exception as e:
        print("load_db error:", e)
        return {}   

def save_db(data):
    try:
        raw = json.dumps(data, indent=2).encode("utf-8")
        encrypted = fernet.encrypt(raw)
        with open(DB_FILE, "wb") as f:
            f.write(encrypted)
        return True
    except Exception as e:
        print("save_db error:", e)
        return False

@app.route("/check_key", methods=["POST"])
def check_key():
    key = request.form.get("key")
    if not key:
        return jsonify({"status": "error", "message": "Missing key"}), 400

    db = load_db()
    if key in db:
        data = db[key]
        try:
            expire_date = datetime.strptime(data["expire_date"], "%Y-%m-%d")
        except:
            return jsonify({"status": "error", "message": "Bad expire_date format"}), 500

        if data.get("status") != "active":
            return jsonify({"status": "invalid"})
        if datetime.now() <= expire_date:
            return jsonify({"status": "valid", "expire_date": data["expire_date"]})
        else:
            return jsonify({"status": "expired"})
    else:
        return jsonify({"status": "invalid"})

@app.route("/add_key", methods=["GET"])
def add_key():
    admin_pass = request.args.get("admin_pass")
    if admin_pass != ADMIN_PASS:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    key = request.args.get("key")
    expire_date = request.args.get("expire_date")  # format YYYY-MM-DD
    if not key or not expire_date:
        return jsonify({"status": "error", "message": "Missing key or expire_date"}), 400

    db = load_db()
    db[key] = {"expire_date": expire_date, "status": "active"}
    if save_db(db):
        return jsonify({"status": "success", "message": f"Key {key} added with expire date {expire_date}"})
    else:
        return jsonify({"status": "error", "message": "Failed to save DB"}), 500

@app.route("/list_keys", methods=["GET"])
def list_keys():
    admin_pass = request.args.get("admin_pass")
    if admin_pass != ADMIN_PASS:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    db = load_db()
    return jsonify({"status": "success", "data": db})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
