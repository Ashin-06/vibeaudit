import os
import secrets
import sqlite3
import subprocess

import bcrypt
import stripe
from flask import Flask, abort, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import current_user, login_required
from markupsafe import escape
from openai import OpenAI
from pydantic import BaseModel, ValidationError

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
CORS(app, origins=["https://app.example.com"])
limiter = Limiter(get_remote_address, app=app, default_limits=["60 per minute"])
client = OpenAI()
SYSTEM_PROMPT = "You are a helpful assistant for a cooking site. Only answer cooking questions."


class ChatIn(BaseModel):
    message: str


class LoginIn(BaseModel):
    email: str
    password: str


def db():
    return sqlite3.connect(os.environ.get("DB_PATH", "app.db"))


@app.post("/api/chat")
@login_required
@limiter.limit("10 per minute")
def chat():
    try:
        body = ChatIn.model_validate(request.get_json())
    except ValidationError:
        abort(400)
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=400,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": body.message},
        ],
    )
    answer = completion.choices[0].message.content or ""
    return jsonify({"answer": str(escape(answer))})


@app.delete("/api/notes/<int:note_id>")
@login_required
def delete_note(note_id):
    conn = db()
    conn.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, current_user.id))
    conn.commit()
    return "", 204


@app.post("/api/export")
@login_required
def export():
    result = subprocess.run(["pandoc", "--version"], check=True, capture_output=True, text=True)
    return jsonify({"version": result.stdout.splitlines()[0]})


@app.post("/login")
@limiter.limit("5 per minute")
def login():
    data = LoginIn.model_validate(request.get_json())
    row = db().execute("SELECT id, password_hash FROM users WHERE email = ?", (data.email,)).fetchone()
    if row is None or not bcrypt.checkpw(data.password.encode(), row[1]):
        abort(401)
    return jsonify({"ok": True})


@app.post("/webhooks/stripe")
def stripe_webhook():
    payload = request.get_data()
    signature = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, signature, os.environ["STRIPE_WEBHOOK_SECRET"])
    except ValueError:
        abort(400)
    return jsonify({"received": event["type"]})


@app.get("/health")
def health():
    return jsonify({"ok": True})


def new_reset_token():
    return secrets.token_urlsafe(32)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
