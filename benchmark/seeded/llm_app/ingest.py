from langchain_chroma import Chroma
from langchain_community.document_loaders import WebBaseLoader


def ingest(url, embeddings):
    docs = WebBaseLoader(url).load()
    return Chroma.from_documents(docs, embeddings)  # expect: LLM022
