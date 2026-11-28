import re

def bad_regex():
    return re.compile(r"([0-9]+)+#")  # expect: BE023
