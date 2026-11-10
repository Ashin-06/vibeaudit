import json
import subprocess

import torch
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from langchain_core.tools import tool
from langchain_experimental.agents import create_pandas_dataframe_agent
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from transformers import AutoModel

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)  # expect: BE012
llm = ChatOpenAI(model="gpt-4o-mini")  # expect: LLM003
model = AutoModel.from_pretrained("someorg/some-model", trust_remote_code=True)  # expect: LLM008
weights = torch.load("weights.pt")  # expect: LLM008
df = None


@tool
def run_shell(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout  # expect: LLM005


@tool
def read_file(path: str) -> str:
    """Read a file from disk."""
    with open(path) as fh:  # expect: LLM005
        return fh.read()


agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)  # expect: LLM006


def build_messages(user_input: str):
    return [{"role": "system", "content": f"Answer as an expert. Context: {user_input}"}]  # expect: LLM001


class Ask(BaseModel):
    question: str


@app.post("/ask")
async def ask(body: Ask):  # expect: AUTH001, LLM004
    while True:  # expect: LLM009
        result = agent.invoke(body.question)
        if "FINAL" in str(result):
            return {"answer": result}


LEGACY_MODEL = "text-davinci-003"  # expect: LLM012
executor = create_react_agent(llm, [run_shell, read_file])  # expect: LLM015


def parse_plan(question: str):
    reply = llm.invoke(question).content
    return json.loads(reply)  # expect: LLM011
