import redis

r = redis.Redis()


def remember(user, token):
    r.set(f"session:{user}", token)  # expect: DATA013
