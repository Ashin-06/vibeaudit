from pinecone import Pinecone

index = Pinecone().Index("profiles")


def save_profile(user, vector):
    index.upsert(vectors=[{"id": user.id, "values": vector,
                           "metadata": {"email": user.email, "plan": user.plan}}])  # expect: DATA014
