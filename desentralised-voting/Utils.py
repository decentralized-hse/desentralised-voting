import json
from Cryptodome.Hash import SHA256


def get_hash(content):
    return SHA256.new(data=json.dumps(content).encode())
