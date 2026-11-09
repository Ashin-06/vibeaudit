import os
import pickle
import random
import sqlite3

import requests
import yaml
from flask import Flask, jsonify, redirect, render_template_string, request
from flask_cors import CORS
from openai import OpenAI

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"  # expect: SEC004
CORS(app, supports_credentials=True)  # expect: BE012
OPENAI_API_KEY = "{{FAKE_OPENAI_KEY}}"  # expect: SEC001
client = OpenAI(api_key=OPENAI_API_KEY)
ADMIN_PASSWORD = "hunter2-admin"  # expect: SEC011


def get_db():
    return sqlite3.connect("app.db")


def verify_token(token):  # expect: AUTH008
    # TODO: add real auth before launch  # expect: QA004
    return True


@app.route("/api/chat", methods=["POST"])
def chat():  # expect: AUTH001, LLM004, BE018
    data = request.get_json()
    question = data["question"]
    completion = client.chat.completions.create(  # expect: LLM003
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": f"You are a helpful assistant. The user asked: {question}"},  # expect: LLM001
            {"role": "user", "content": question},
        ],
    )
    answer = completion.choices[0].message.content
    return jsonify({"answer": answer})


@app.route("/api/run", methods=["POST"])
def run_code():  # expect: AUTH001, LLM004
    code = request.json["code"]
    plan = client.chat.completions.create(model="gpt-4o-mini", max_tokens=200, messages=[{"role": "user", "content": code}])
    script = plan.choices[0].message.content
    exec(script)  # expect: LLM002
    os.system("echo " + request.args.get("name", ""))  # expect: BE002
    return "ok"


@app.route("/api/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):  # expect: AUTH001
    db = get_db()
    db.execute(f"DELETE FROM users WHERE id = {user_id}")  # expect: BE001
    db.commit()
    return "", 204


@app.route("/admin/users")
def admin_users():  # expect: AUTH002
    rows = get_db().execute("SELECT * FROM users").fetchall()
    return jsonify(rows)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)  # expect: BE005
    return resp.text


@app.route("/go")
def go():
    return redirect(request.args.get("next"))  # expect: BE008


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")  # expect: BE007


@app.route("/upload", methods=["POST"])
def upload():
    blob = request.get_data()
    obj = pickle.loads(blob)  # expect: BE004
    config = yaml.load(request.form["cfg"])  # expect: BE004
    return jsonify({"ok": True, "n": len(obj), "c": str(config)})


@app.route("/login", methods=["POST"])
def login():  # expect: AUTH010
    user = get_db().execute("SELECT * FROM users WHERE email = ?", (request.form["email"],)).fetchone()
    if user and user.password == request.form["password"]:  # expect: BE014
        return jsonify({"token": make_reset_token()})
    return jsonify({"error": "bad credentials"}), 401


def make_reset_token():
    token = "".join(random.choice("abcdef0123456789") for _ in range(16))  # expect: BE015
    return token


@app.route("/report")
def report():
    try:
        return jsonify(compute())
    except Exception as e:
        return jsonify({"error": str(e)})  # expect: BE017


def compute():
    return {}


def cleanup():
    try:
        os.remove("tmp.txt")
    except Exception:  # expect: QA003
        pass


if __name__ == "__main__":
    print("Starting with key", OPENAI_API_KEY)  # expect: SEC010
    app.run(debug=True)  # expect: BE011
