#!/usr/bin/env python3
"""
Serveur de licences — Spoofer de F2P
Stockage Supabase (PostgreSQL gratuit, persistant)
"""
import os, json, secrets, string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

ADMIN_KEY = os.environ.get("ADMIN_KEY", "admin-secret")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

def supabase_req(method, path, data=None):
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code
    except Exception as e:
        return {"error": str(e)}, 500

def get_key(key):
    result, status = supabase_req("GET", f"licenses?key=eq.{key}&limit=1")
    if isinstance(result, list) and len(result) > 0:
        return result[0]
    return None

def create_key_db(entry):
    result, status = supabase_req("POST", "licenses", entry)
    return status in (200, 201)

def update_key_db(key, updates):
    result, status = supabase_req("PATCH", f"licenses?key=eq.{key}", updates)
    return status in (200, 204)

def list_keys_db():
    result, status = supabase_req("GET", "licenses?limit=500")
    return result if isinstance(result, list) else []

def generate_key(prefix="F2P"):
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(3)]
    return f"{prefix}-{'-'.join(parts)}"

@app.route("/")
@app.route("/health")
def health():
    return jsonify({"status": "ok", "server_time": datetime.utcnow().isoformat(), "storage": "supabase"})

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "")
    if not key:
        return jsonify({"valid": False, "reason": "Clé manquante"}), 400

    entry = get_key(key)
    if not entry:
        return jsonify({"valid": False, "reason": "Clé invalide"}), 404

    if entry.get("type") == "trial":
        expires = datetime.fromisoformat(entry["expires_at"].replace("Z",""))
        if datetime.utcnow() > expires:
            return jsonify({"valid": False, "reason": "Clé d'essai expirée"}), 403

    if entry.get("revoked", False):
        return jsonify({"valid": False, "reason": "Clé révoquée"}), 403

    if not entry.get("machine_id"):
        update_key_db(key, {"machine_id": machine_id, "activated_at": datetime.utcnow().isoformat(), "uses": 1})
    elif entry["machine_id"] != machine_id:
        return jsonify({"valid": False, "reason": "Clé déjà utilisée sur un autre appareil"}), 403
    else:
        update_key_db(key, {"uses": entry.get("uses", 0) + 1, "last_seen": datetime.utcnow().isoformat()})

    days_left = None
    if entry.get("type") == "trial":
        expires = datetime.fromisoformat(entry["expires_at"].replace("Z",""))
        days_left = max(0, (expires - datetime.utcnow()).days)

    return jsonify({"valid": True, "type": entry["type"], "days_left": days_left})

@app.route("/admin/create", methods=["POST"])
def create_key_route():
    data = request.get_json(silent=True) or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify({"error": "Non autorisé"}), 403

    key_type = data.get("type", "lifetime")
    note = data.get("note", "")
    count = min(int(data.get("count", 1)), 50)
    created = []

    for _ in range(count):
        key = generate_key("F2P" if key_type == "lifetime" else "TRY")
        entry = {
            "key": key, "type": key_type,
            "created_at": datetime.utcnow().isoformat(),
            "note": note, "machine_id": None, "revoked": False, "uses": 0
        }
        if key_type == "trial":
            entry["expires_at"] = (datetime.utcnow() + timedelta(days=3)).isoformat()
        if create_key_db(entry):
            created.append(key)

    return jsonify({"created": created, "count": len(created)})

@app.route("/admin/list", methods=["POST"])
def list_keys_route():
    data = request.get_json(silent=True) or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify({"error": "Non autorisé"}), 403
    keys = list_keys_db()
    return jsonify({"keys": {k["key"]: k for k in keys}, "total": len(keys)})

@app.route("/admin/revoke", methods=["POST"])
def revoke_key_route():
    data = request.get_json(silent=True) or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify({"error": "Non autorisé"}), 403
    key = data.get("key", "").strip().upper()
    if not get_key(key):
        return jsonify({"error": "Clé introuvable"}), 404
    update_key_db(key, {"revoked": True})
    return jsonify({"revoked": key})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

print("=== Serveur licences Supabase démarré ===")
