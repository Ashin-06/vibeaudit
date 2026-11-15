from flask import Flask, request

from .db import orders
from .db.orders import order_by_id, order_by_ref

app = Flask(__name__)


def summarise(text):
    return eval(text)  # expect: LLM002


@app.get("/orders/<ref>")
def show(ref):
    order_by_ref(app.db, ref)
    order_by_id(app.db, int(ref))
    return "ok"


@app.post("/export")
def export():
    orders.export(request.form["format"])
    return "ok"


@app.post("/summary")
def summary():
    from openai import OpenAI

    out = OpenAI().chat.completions.create(model="gpt-4o-mini", max_tokens=50, messages=[]).choices[0].message.content
    summarise(out)
    return "ok"
