#!/usr/bin/env python3
"""
Serveur de licences — Spoofer de F2P
Déployé sur Render.com (gratuit)
Version corrigée pour Gunicorn + Render (février 2026)
"""

import os
import json
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

# Clé admin — À CHANGER OBLIGATOIREMENT via variable d'environnement sur Render
ADMIN_KEY = os.environ.get("ADMIN_KEY", "admin-secret-change-me-please")

# Fichier de stockage (Render accepte /tmp/ pour les fichiers persistants sur free tier)
DB_FILE = "/tmp/licenses.json"

def load_db():
    """Charge la base JSON ou retourne un dict vide si absent/erreur"""
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Erreur lecture DB : {e}")
        return {}

def save_db(db):
    """Sauvegarde la base JSON"""
    try:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Erreur sauvegarde DB : {e}")

def generate_key(prefix="F2P"):
    """Génère une clé lisible au format XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(3)]
    return f"{prefix}-{'-'.join(parts)}"

# ── ROUTES ────────────────────────────────────────────────────────────────

@app.route("/health")
@app.route("/")
def health():
    db = load_db()
    return jsonify({
        "status": "ok",
        "total_keys": len(db),
        "server_time": datetime.utcnow().isoformat(),
        "render_port": os.environ.get("PORT", "non défini")
    })


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "")

    if not key:
        return jsonify({"valid": False, "reason": "Clé manquante"}), 400

    db = load_db()
    if key not in db:
        return jsonify({"valid": False, "reason": "Clé invalide"}), 404

    entry = db[key]

    # Vérification expiration trial
    if entry.get("type") == "trial":
        try:
            expires = datetime.fromisoformat(entry["expires_at"])
            if datetime.utcnow() > expires:
                return jsonify({"valid": False, "reason": "Clé d'essai expirée"}), 403
        except:
            return jsonify({"valid": False, "reason": "Format expiration invalide"}), 500

    # Vérification révocation
    if entry.get("revoked", False):
        return jsonify({"valid": False, "reason": "Clé révoquée"}), 403

    # Première activation → bind machine_id
    if not entry.get("machine_id"):
        db[key]["machine_id"] = machine_id
        db[key]["activated_at"] = datetime.utcnow().isoformat()
        db[key]["uses"] = 1
    elif entry["machine_id"] != machine_id:
        return jsonify({"valid": False, "reason": "Clé déjà utilisée sur un autre appareil"}), 403
    else:
        db[key]["uses"] = entry.get("uses", 0) + 1
        db[key]["last_seen"] = datetime.utcnow().isoformat()

    save_db(db)

    # Jours restants pour trial
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
    data = request.get_json(silent=True) or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify({"error": "Non autorisé"}), 403

    key_type = data.get("type", "lifetime")
    note = data.get("note", "")
    count = min(int(data.get("count", 1)), 50)  # limite raisonnable

    if key_type not in ("lifetime", "trial"):
        return jsonify({"error": "Type invalide (lifetime ou trial)"}), 400

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
            "uses": 0
        }
        if key_type == "trial":
            entry["expires_at"] = (datetime.utcnow() + timedelta(days=3)).isoformat()
        db[key] = entry
        created.append(key)

    save_db(db)
    return jsonify({"created": created, "count": len(created)})


@app.route("/admin/list", methods=["GET", "POST"])
def list_keys():
    data = request.get_json(silent=True) or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify({"error": "Non autorisé"}), 403

    db = load_db()
    return jsonify({"keys": db, "total": len(db)})


@app.route("/admin/revoke", methods=["POST"])
def revoke_key():
    data = request.get_json(silent=True) or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify({"error": "Non autorisé"}), 403

    key = data.get("key", "").strip().upper()
    if not key:
        return jsonify({"error": "Clé requise"}), 400

    db = load_db()
    if key not in db:
        return jsonify({"error": "Clé introuvable"}), 404

    db[key]["revoked"] = True
    save_db(db)
    return jsonify({"revoked": key, "status": "révoquée"})


# ── Lancement (pour debug local uniquement) ───────────────────────────────
# NE PAS UTILISER EN PRODUCTION SUR RENDER → Gunicorn le remplace
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Mode développement local — http://0.0.0.0:{port}")
    print("ADMIN_KEY =", ADMIN_KEY)
    app.run(host="0.0.0.0", port=port, debug=True)

# Log de démarrage (visible dans les logs Render)
print("=== Serveur licences démarré ===")
print(f"ADMIN_KEY configuré : {bool(ADMIN_KEY and ADMIN_KEY != 'admin-secret-change-me-please')}")
print(f"DB_FILE : {DB_FILE} (existe ? {os.path.exists(DB_FILE)})")
