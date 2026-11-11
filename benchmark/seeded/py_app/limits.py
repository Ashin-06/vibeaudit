# Seeded: the rate limit key is a header the client controls.
def client_key(request):
    return request.headers.get("X-Forwarded-For", "unknown")  # expect: AUTH014


limiter = Limiter(key_func=client_key)  # rate limit
