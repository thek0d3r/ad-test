"""INQ Online -- banking + e-Signing attack/defense service.

A deliberately vulnerable service for the CTF@AC saarCTF platform.
One account logs into both halves of the portal.

FOUR flag stores, reached only through the service's own HTTP API:

  store 0 (PlaceID 1)  a transfer's `memo`       (Payments)
       put: POST /api/transfers      get: GET /api/transfers/<id>        (sender)
  store 1 (PlaceID 2)  a mandate's `secret`       (Payments)
       put: POST /api/mandates       get: GET /api/mandates/<id>         (owner)
  store 2 (PlaceID 3)  an order's `secret`        (e-Signing)
       put: POST /api/orders         get: GET /api/orders/<id>/secret    (owner)
  store 3 (PlaceID 4)  an order's `vault`         (e-Signing)
       put: POST /api/orders         get: authorise + GET /api/vault/<id> (owner)

Discovery is deliberate: ids are random. The public settlement feed and the
public order registry publish ids and non-sensitive metadata, never the memo,
secret or vault.

RESOURCE BOUNDS (a count cap is not a memory bound if the rows are unbounded)
  MAX_USERS 4096 · per-user caps 64 · MAX_MEMO 512 · MAX_SECRET 1024 · MAX_FIELD 256
A full table REFUSES; it never evicts.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import time

from flask import Flask, g, jsonify, request, send_from_directory

DB_PATH = os.environ.get("WEBCRYPTO_DB", "/data/webcrypto.sqlite3")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

MAX_USERS = 4096
MAX_TRANSFERS_PER_USER = 64
MAX_MANDATES_PER_USER = 64
MAX_ORDERS_PER_USER = 64
MAX_FIELD = 256
MAX_AMOUNT = 32
MAX_MEMO = 512
MAX_SECRET = 1024

# e-Signing gateway key (server-held, never exposed) and the public specimen.
GATEWAY_KEY = hashlib.sha256(b"inq-e-signing-gateway-key-v1").digest()
SPECIMEN_TEXT = ("SPECIMEN ORDER -- INQ e-Signing reference instrument. "
                 "This document is a non-negotiable example used to validate "
                 "signature tooling and carries no value whatsoever. " + "=" * 96)

app = Flask(__name__, static_folder=None)


# ----------------------------------------------------------- crypto helpers

def keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"),
                        hashlib.sha256).digest()
        counter += 1
    return bytes(out[:n])


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def user_nonce(username: str) -> bytes:
    return hmac.new(GATEWAY_KEY, b"nonce|" + username.encode(),
                    hashlib.sha256).digest()[:16]


def blob_nonce(order) -> bytes:
    return user_nonce(order["owner"])


def share_key(order_id: str) -> bytes:
    return hashlib.sha256(b"share|" + order_id.encode()).digest()


def ticket_for(order_id: str) -> str:
    return hmac.new(GATEWAY_KEY, b"ticket|" + order_id.encode(),
                    hashlib.sha256).hexdigest()


def legacy_ticket(order_id: str) -> str:
    return hashlib.sha256(b"legacy|" + order_id.encode()).hexdigest()[:32]


# --------------------------------------------------------------------- storage

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA busy_timeout=5000")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            iban     TEXT NOT NULL UNIQUE,
            pwhash   TEXT NOT NULL,
            token    TEXT NOT NULL UNIQUE,
            created  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transfers (
            id          TEXT PRIMARY KEY,
            sender      TEXT NOT NULL,
            beneficiary TEXT NOT NULL,
            amount      TEXT NOT NULL,
            memo        TEXT NOT NULL,
            digest      TEXT NOT NULL,
            created     INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mandates (
            id          TEXT PRIMARY KEY,
            owner       TEXT NOT NULL,
            transfer_id TEXT NOT NULL,
            reference   TEXT NOT NULL,
            secret      TEXT NOT NULL,
            digest      TEXT NOT NULL,
            created     INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orders (
            id      TEXT PRIMARY KEY,
            owner   TEXT NOT NULL,
            label   TEXT NOT NULL,
            kind    TEXT NOT NULL,
            secret  TEXT NOT NULL,
            vault   TEXT NOT NULL,
            nonce   TEXT NOT NULL,
            created INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS transfers_sender ON transfers(sender);
        CREATE INDEX IF NOT EXISTS mandates_owner ON mandates(owner);
        CREATE INDEX IF NOT EXISTS orders_owner ON orders(owner);
        """
    )
    conn.commit()
    conn.close()


# ----------------------------------------------------------------------- utils

def err(message, code):
    return jsonify({"error": message}), code


def field(payload, name, limit=MAX_FIELD):
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        return None, err(f"{name} is required and must be a non-empty string", 400)
    if len(value) > limit:
        return None, err(f"{name} exceeds {limit} bytes", 413)
    return value, None


def pwhash(username, password):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), b"webcrypto|" + username.encode(), 60_000).hex()


def digest_of(text):
    return hashlib.sha256(text.encode()).hexdigest()


def make_iban():
    body = "".join(secrets.choice("0123456789") for _ in range(16))
    return "RO49INQB" + body


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    if not token:
        return None
    row = db().execute("SELECT username FROM users WHERE token = ?", (token,)).fetchone()
    return row["username"] if row else None


def require_user():
    user = current_user()
    if user is None:
        return None, err("authentication required", 401)
    return user, None


def insert_order(conn, owner, label, kind, secret, vault):
    oid = secrets.token_hex(16)
    conn.execute(
        "INSERT INTO orders (id, owner, label, kind, secret, vault, nonce, created) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (oid, owner, label, kind, secret, vault, secrets.token_hex(16),
         int(time.time())),
    )
    return oid


# ------------------------------------------------------------------ UI serving

@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.get("/static/<path:name>")
def static_files(name):
    return send_from_directory(STATIC_DIR, name)


# ---------------------------------------------------------------------- health

@app.get("/health")
def health():
    conn = db()
    return jsonify({
        "service": "webcrypto",
        "status": "ok",
        "version": "1.0",
        "users": conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "transfers": conn.execute("SELECT COUNT(*) c FROM transfers").fetchone()["c"],
        "mandates": conn.execute("SELECT COUNT(*) c FROM mandates").fetchone()["c"],
        "orders": conn.execute("SELECT COUNT(*) c FROM orders").fetchone()["c"],
    })


# ------------------------------------------------------------------ accounts

@app.post("/api/register")
def register():
    payload = request.get_json(silent=True) or {}
    username, bad = field(payload, "username")
    if bad:
        return bad
    password, bad = field(payload, "password")
    if bad:
        return bad

    conn = db()
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] >= MAX_USERS:
        return err("the customer registry is full", 507)
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        return err("username already taken", 409)

    token = secrets.token_hex(24)
    iban = make_iban()
    conn.execute(
        "INSERT INTO users (username, iban, pwhash, token, created) VALUES (?,?,?,?,?)",
        (username, iban, pwhash(username, password), token, int(time.time())),
    )
    # every account gets an e-Signing specimen order: a public known-plaintext.
    insert_order(conn, username, "specimen", "specimen", SPECIMEN_TEXT, "-")
    conn.commit()
    return jsonify({"username": username, "iban": iban, "token": token}), 201


@app.post("/api/login")
def login():
    payload = request.get_json(silent=True) or {}
    username, bad = field(payload, "username")
    if bad:
        return bad
    password, bad = field(payload, "password")
    if bad:
        return bad

    row = db().execute(
        "SELECT iban, pwhash, token FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None or not hmac.compare_digest(row["pwhash"], pwhash(username, password)):
        return err("bad credentials", 401)
    return jsonify({"username": username, "iban": row["iban"], "token": row["token"]})


@app.get("/api/profile")
def profile():
    user, bad = require_user()
    if bad:
        return bad
    row = db().execute(
        "SELECT username, iban, created FROM users WHERE username = ?", (user,)
    ).fetchone()
    return jsonify({"username": row["username"], "iban": row["iban"],
                    "created": row["created"]})


# ===================================================================== PAYMENTS

@app.post("/api/transfers")
def create_transfer():
    user, bad = require_user()
    if bad:
        return bad
    payload = request.get_json(silent=True) or {}
    beneficiary, bad = field(payload, "beneficiary")
    if bad:
        return bad
    amount, bad = field(payload, "amount", limit=MAX_AMOUNT)
    if bad:
        return bad
    memo, bad = field(payload, "memo", limit=MAX_MEMO)
    if bad:
        return bad

    conn = db()
    held = conn.execute(
        "SELECT COUNT(*) c FROM transfers WHERE sender = ?", (user,)
    ).fetchone()["c"]
    if held >= MAX_TRANSFERS_PER_USER:
        return err(f"at most {MAX_TRANSFERS_PER_USER} transfers per account", 507)

    tid = secrets.token_hex(16)
    now = int(time.time())
    conn.execute(
        "INSERT INTO transfers (id, sender, beneficiary, amount, memo, digest, created) "
        "VALUES (?,?,?,?,?,?,?)",
        (tid, user, beneficiary, amount, memo, digest_of(memo), now),
    )
    conn.commit()
    return jsonify({"id": tid, "beneficiary": beneficiary, "amount": amount,
                    "digest": digest_of(memo), "created": now}), 201


@app.get("/api/transfers")
def list_transfers():
    user, bad = require_user()
    if bad:
        return bad
    rows = db().execute(
        "SELECT id, beneficiary, amount, digest, created FROM transfers "
        "WHERE sender = ? ORDER BY created DESC",
        (user,),
    ).fetchall()
    return jsonify({"transfers": [dict(r) for r in rows]})


@app.get("/api/transfers/<tid>")
def read_transfer(tid):
    user, bad = require_user()
    if bad:
        return bad
    row = db().execute("SELECT * FROM transfers WHERE id = ?", (tid,)).fetchone()
    if row is None:
        return err("no such transfer", 404)
    return jsonify({
        "id": row["id"],
        "sender": row["sender"],
        "beneficiary": row["beneficiary"],
        "amount": row["amount"],
        "memo": row["memo"],
        "digest": row["digest"],
        "created": row["created"],
    })


@app.get("/api/transfers/<tid>/mandate")
def read_transfer_mandate(tid):
    user, bad = require_user()
    if bad:
        return bad
    transfer = db().execute(
        "SELECT * FROM transfers WHERE id = ?", (tid,)).fetchone()
    if transfer is None:
        return err("no such transfer", 404)
    row = db().execute(
        "SELECT * FROM mandates WHERE transfer_id = ?", (tid,)).fetchone()
    if row is None:
        return err("no mandate on this transfer", 404)
    return jsonify({
        "mandate_id": row["id"],
        "transfer_id": row["transfer_id"],
        "reference": row["reference"],
        "secret": row["secret"],
        "digest": row["digest"],
        "created": row["created"],
    })


@app.get("/api/feed")
def feed():
    try:
        limit = int(request.args.get("limit", "50"))
    except ValueError:
        return err("limit must be a number", 400)
    limit = max(1, min(limit, 200))

    conn = db()
    transfers = conn.execute(
        "SELECT id, sender, beneficiary, amount, digest, created FROM transfers "
        "ORDER BY created DESC LIMIT ?", (limit,)
    ).fetchall()
    mandates = conn.execute(
        "SELECT id, owner, transfer_id, reference, digest, created FROM mandates "
        "ORDER BY created DESC LIMIT ?", (limit,)
    ).fetchall()
    return jsonify({
        "transfers": [dict(r) for r in transfers],
        "mandates": [dict(r) for r in mandates],
        "limit": limit,
    })


@app.get("/api/feed/<tid>")
def feed_detail(tid):
    row = db().execute("SELECT * FROM transfers WHERE id = ?", (tid,)).fetchone()
    if row is None:
        return err("no such transfer", 404)
    return jsonify({
        "id": row["id"],
        "sender": row["sender"],
        "beneficiary": row["beneficiary"],
        "amount": row["amount"],
        "memo": row["memo"],
        "digest": row["digest"],
        "valid": row["digest"] == digest_of(row["memo"]),
        "created": row["created"],
    })


@app.post("/api/mandates")
def create_mandate():
    user, bad = require_user()
    if bad:
        return bad
    payload = request.get_json(silent=True) or {}
    transfer_id, bad = field(payload, "transfer_id")
    if bad:
        return bad
    secret, bad = field(payload, "secret", limit=MAX_SECRET)
    if bad:
        return bad

    conn = db()
    transfer = conn.execute(
        "SELECT sender FROM transfers WHERE id = ?", (transfer_id,)
    ).fetchone()
    if transfer is None:
        return err("no such transfer", 404)
    if transfer["sender"] != user:
        return err("you can only add a mandate to your own transfer", 403)
    if conn.execute("SELECT 1 FROM mandates WHERE transfer_id = ?",
                    (transfer_id,)).fetchone():
        return err("this transfer already has a mandate", 409)

    held = conn.execute(
        "SELECT COUNT(*) c FROM mandates WHERE owner = ?", (user,)
    ).fetchone()["c"]
    if held >= MAX_MANDATES_PER_USER:
        return err(f"at most {MAX_MANDATES_PER_USER} mandates per account", 507)

    mandate_id = secrets.token_hex(16)
    reference = "MND" + secrets.token_hex(6).upper()
    conn.execute(
        "INSERT INTO mandates (id, owner, transfer_id, reference, secret, digest, created) "
        "VALUES (?,?,?,?,?,?,?)",
        (mandate_id, user, transfer_id, reference, secret, digest_of(secret),
         int(time.time())),
    )
    conn.commit()
    return jsonify({"mandate_id": mandate_id, "transfer_id": transfer_id,
                    "reference": reference, "digest": digest_of(secret)}), 201


@app.get("/api/mandates")
def list_mandates():
    user, bad = require_user()
    if bad:
        return bad
    rows = db().execute(
        "SELECT id, transfer_id, reference, digest, created FROM mandates "
        "WHERE owner = ? ORDER BY created DESC",
        (user,),
    ).fetchall()
    return jsonify({"mandates": [dict(r) for r in rows]})


@app.get("/api/mandates/<mandate_id>")
def read_mandate(mandate_id):
    user, bad = require_user()
    if bad:
        return bad
    row = db().execute("SELECT * FROM mandates WHERE id = ?", (mandate_id,)).fetchone()
    if row is None:
        return err("no such mandate", 404)
    if row["owner"] != user:
        return err("not your mandate", 403)
    return jsonify({
        "mandate_id": row["id"],
        "transfer_id": row["transfer_id"],
        "reference": row["reference"],
        "secret": row["secret"],
        "digest": row["digest"],
        "created": row["created"],
    })


@app.get("/api/verify/<mandate_id>")
def verify_mandate(mandate_id):
    row = db().execute("SELECT * FROM mandates WHERE id = ?", (mandate_id,)).fetchone()
    if row is None:
        return err("no such mandate", 404)
    return jsonify({
        "mandate_id": row["id"],
        "transfer_id": row["transfer_id"],
        "reference": row["reference"],
        "secret": row["secret"],
        "digest": row["digest"],
        "valid": row["digest"] == digest_of(row["secret"]),
        "created": row["created"],
    })


# ==================================================================== E-SIGNING

@app.post("/api/orders")
def create_order():
    user, bad = require_user()
    if bad:
        return bad
    payload = request.get_json(silent=True) or {}
    label, bad = field(payload, "label")
    if bad:
        return bad
    secret, bad = field(payload, "secret", limit=MAX_SECRET)
    if bad:
        return bad
    vault, bad = field(payload, "vault", limit=MAX_SECRET)
    if bad:
        return bad

    conn = db()
    held = conn.execute(
        "SELECT COUNT(*) c FROM orders WHERE owner = ?", (user,)
    ).fetchone()["c"]
    if held >= MAX_ORDERS_PER_USER:
        return err(f"at most {MAX_ORDERS_PER_USER} orders per account", 507)

    oid = insert_order(conn, user, label, "order", secret, vault)
    conn.commit()
    return jsonify({"id": oid, "label": label, "created": int(time.time())}), 201


@app.get("/api/orders")
def list_orders():
    user, bad = require_user()
    if bad:
        return bad
    rows = db().execute(
        "SELECT id, label, kind, created FROM orders WHERE owner = ? "
        "ORDER BY created DESC", (user,),
    ).fetchall()
    return jsonify({"orders": [dict(r) for r in rows]})


@app.get("/api/orders/<oid>/secret")
def read_secret(oid):
    user, bad = require_user()
    if bad:
        return bad
    row = db().execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
    if row is None:
        return err("no such order", 404)
    if row["owner"] != user:
        return err("not your order", 403)
    return jsonify({"id": row["id"], "label": row["label"],
                    "secret": row["secret"], "created": row["created"]})


@app.get("/api/orders/<oid>/blob")
def order_blob(oid):
    row = db().execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
    if row is None:
        return err("no such order", 404)
    nonce = bytes.fromhex(row["nonce"])  # FIXED: per-order nonce
    ct = xor(row["secret"].encode(), keystream(GATEWAY_KEY, nonce, len(row["secret"].encode())))
    return jsonify({"id": row["id"], "owner": row["owner"],
                    "nonce": nonce.hex(), "ciphertext": ct.hex()})


@app.get("/api/orders/<oid>/share")
def order_share(oid):
    row = db().execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
    if row is None:
        return err("no such order", 404)
    sk = share_key(row["id"])
    token = xor(row["secret"].encode(), keystream(sk, b"\x00" * 16, len(row["secret"].encode())))
    return jsonify({"id": row["id"], "token": token.hex()})


@app.get("/api/registry")
def registry():
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        return err("limit must be a number", 400)
    limit = max(1, min(limit, 500))
    rows = db().execute(
        "SELECT id, owner, label, kind, created FROM orders "
        "ORDER BY created DESC LIMIT ?", (limit,)
    ).fetchall()
    return jsonify({"orders": [dict(r) for r in rows], "limit": limit})


@app.post("/api/orders/<oid>/authorize")
def authorize(oid):
    user, bad = require_user()
    if bad:
        return bad
    row = db().execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
    if row is None:
        return err("no such order", 404)
    return jsonify({"id": row["id"], "ticket": ticket_for(row["id"])})


@app.get("/api/vault/<oid>")
def release_vault(oid):
    row = db().execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
    if row is None:
        return err("no such order", 404)
    ticket = request.args.get("ticket", "")
    legacy = request.args.get("legacy", "")
    good = False
    if ticket and hmac.compare_digest(ticket, ticket_for(row["id"])):
        good = True
    if legacy and hmac.compare_digest(legacy, legacy_ticket(row["id"])):
        good = True
    if not good:
        return err("invalid or missing ticket", 403)
    return jsonify({"id": row["id"], "vault": row["vault"]})


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("WEBCRYPTO_PORT", "9421")))
