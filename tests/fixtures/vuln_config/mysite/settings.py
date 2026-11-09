import os

SECRET_KEY = "django-insecure-8f3k2j1h0g9f8d7s6a5"  # expect: SEC004
DEBUG = True  # expect: BE011
ALLOWED_HOSTS = ["*"]  # expect: CFG006
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.path.join("db.sqlite3")}}
