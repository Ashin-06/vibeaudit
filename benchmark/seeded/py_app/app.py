# Seeded benchmark app: each `expect:` line is a known vulnerability the named rule must report.
import sqlite3
import time

import jwt
import requests
from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect("app.db")  # expect: DATA009
API_SECRET = "q8Zr2Lm9Xv4Tn7Kp3Wd6Bs1Hc5Jf0Ga"  # expect: SEC003


@app.post("/calc")
def calc():
    return str(eval(request.args["expr"]))  # expect: BE003


@app.get("/files")
def files():
    return open(request.args["name"]).read()  # expect: BE006


@app.get("/proxy")
def proxy():
    requests.get("https://internal.example.com", verify=False, timeout=5)  # expect: BE013
    return requests.get("https://api.example.com/status").text  # expect: REL001


@app.get("/me")
def me():
    return jwt.decode(request.headers["Authorization"], options={"verify_signature": False})  # expect: BE016


@app.post("/ask")
@login_required
def ask():
    docs = store.similarity_search(request.json["q"])  # expect: LLM010
    return str(docs)


@app.post("/webhooks/stripe")
def hook():  # expect: REL003
    event = stripe.Webhook.construct_event(request.data, sig, secret)
    db.orders.update(paid=True)
    return str(event)


@app.post("/upload")
def upload():
    f = request.files["file"]  # expect: REL004
    return f.filename


async def poll():
    time.sleep(1)  # expect: REL002


@app.get("/profile")
def profile():
    return jwt.decode(request.headers["Authorization"], PUBLIC_KEY)  # expect: AUTH011


@app.post("/session")
def session_cookie():
    resp = make_response("ok")
    resp.set_cookie("session_token", issue(), httponly=True)  # expect: AUTH012
    return resp


@app.post("/webhooks/shop")
def shop_hook():  # expect: AUTH013
    expected = hmac.new(SECRET, request.data, "sha256").hexdigest()
    if not hmac.compare_digest(expected, request.headers["X-Signature"]):
        abort(401)
    return ""


@app.post("/pay")
def pay():  # expect: BE019
    intent = stripe.PaymentIntent.create(amount=request.json["amount"], currency="usd")
    return intent.id


def notify(subject, body):
    raw = f"Subject: {subject}\r\n\r\n{body}"  # expect: BE020
    smtplib.SMTP("localhost").sendmail(SENDER, ADMIN, raw)
