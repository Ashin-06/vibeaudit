import subprocess

from openai import OpenAI

client = OpenAI()


def checkout(task):
    r = client.chat.completions.create(model="gpt-4o", max_tokens=20, messages=[{"role": "user", "content": task}])
    branch = r.choices[0].message.content
    subprocess.run(["git", "checkout", branch], check=True)  # expect: LLM019


def run(messages, tools):
    resp = client.chat.completions.create(model="gpt-4o", max_tokens=200, messages=messages, tools=tools)
    while resp.choices[0].message.tool_calls:  # expect: LLM020
        messages.append(call_tools(resp))
        resp = client.chat.completions.create(model="gpt-4o", max_tokens=200, messages=messages, tools=tools)
    return resp


def answer(question):
    prompt = f"You are a support assistant. Answer the customer using only the docs. {question}"  # expect: LLM021
    return client.chat.completions.create(model="gpt-4o", max_tokens=200, messages=[{"role": "user", "content": prompt}])


def call_tools(resp):
    return {"role": "tool", "content": "ok", "tool_call_id": resp.choices[0].message.tool_calls[0].id}
