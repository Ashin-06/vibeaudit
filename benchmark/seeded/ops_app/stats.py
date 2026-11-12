import redis

r = redis.Redis()


def order_count(db):
    cached = r.get("orders:count")  # expect: DATA015
    if cached is None:
        cached = db.execute("select count(*) from orders").fetchone()[0]
        r.set("orders:count", cached, ex=60)
    return cached
