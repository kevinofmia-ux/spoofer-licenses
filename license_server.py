#!/usr/bin/env python3
"""
Serveur de licences — Spoofer de F2P
Déployer sur Render.com (gratuit)
"""
import os, json, hashlib, secrets, string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

# Clé admin — change ça avant de déployer
ADMIN_KEY = os.environ.get("ADMIN_KEY", "admin-secret-change-me")

# ── STOCKAGE (fichier JSON simple, suffisant pour débuter) ──
DB_FILE = "/tmp/licenses.json"

def load_db():
    try:
        with open(DB_FILE) as f:
            return json.load(f)
    except:
        return {}

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def generate_key(prefix="F2P"):
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(3)]
    return f"{prefix}-{''.join(parts[:1])}-{''.join(parts[1:2])}-{''.join(parts[2:])}"

# ── ROUTES ──

@app.route("/verify", methods=["POST"])
def verify():
    data = request.json or {}
    key = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "")

    if not key:
        return jsonify({"valid": False, "reason": "Clé manquante"})

    db = load_db()
    if key not in db:
        return jsonify({"valid": False, "reason": "Clé invalide"})

    entry = db[key]

    # Vérif expiration (trial)
    if entry.get("type") == "trial":
        expires = datetime.fromisoformat(entry["expires_at"])
        if datetime.utcnow() > expires:
            return jsonify({"valid": False, "reason": "Clé d'essai expirée"})

    # Vérif révocation
    if entry.get("revoked"):
        return jsonify({"valid": False, "reason": "Clé révoquée"})

    # Bind machine_id à la première activation
    if not entry.get("machine_id"):
        db[key]["machine_id"] = machine_id
        db[key]["activated_at"] = datetime.utcnow().isoformat()
        db[key]["uses"] = 1
        save_db(db)
    elif entry["machine_id"] != machine_id:
        return jsonify({"valid": False, "reason": "Clé déjà utilisée sur un autre appareil"})
    else:
        db[key]["uses"] = entry.get("uses", 0) + 1
        db[key]["last_seen"] = datetime.utcnow().isoformat()
        save_db(db)

    # Calcul jours restants pour trial
    days_left = None
    if entry.get("type") == "trial":
        expires = datetime.fromisoformat(entry["expires_at"])
        days_left = max(0, (expires - datetime.utcnow()).days)

    return jsonify({
        "valid": True,
        "type": entry["type"],
        "days_left": days_left,
        "note": entry.get("note", "")
    })


@app.route("/admin/create", methods=["POST"])
def create_key():
    data = request.json or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify({"error": "Non autorisé"}), 403

    key_type = data.get("type", "lifetime")  # "lifetime" ou "trial"
    note = data.get("note", "")
    count = min(int(data.get("count", 1)), 100)

    db = load_db()
    created = []

    for _ in range(count):
        key = generate_key("F2P" if key_type == "lifetime" else "TRY")
        entry = {
            "type": key_type,
            "created_at": datetime.utcnow().isoformat(),
            "note": note,
            "machine_id": None,
            "revoked": False,
        }
        if key_type == "trial":
            entry["expires_at"] = (datetime.utcnow() + timedelta(days=3)).isoformat()
        db[key] = entry
        created.append(key)

    save_db(db)
    return jsonify({"created": created, "count": len(created)})


@app.route("/admin/list", methods=["POST"])
def list_keys():
    data = request.json or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify({"error": "Non autorisé"}), 403
    db = load_db()
    return jsonify({"keys": db, "total": len(db)})


@app.route("/admin/revoke", methods=["POST"])
def revoke_key():
    data = request.json or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify({"error": "Non autorisé"}), 403
    key = data.get("key", "").upper()
    db = load_db()
    if key not in db:
        return jsonify({"error": "Clé introuvable"}), 404
    db[key]["revoked"] = True
    save_db(db)
    return jsonify({"revoked": key})


@app.route("/health")
def health():
    db = load_db()
    return jsonify({"status": "ok", "total_keys": len(db)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 4000))
    print(f"🔑 Serveur licences — http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
