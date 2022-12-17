import json
import ntplib
import datetime
from Cryptodome.Hash import SHA256


def get_time():
    while True:
        try:
            return datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        except ntplib.NTPException:
            pass


def get_hash(content):
    return SHA256.new(data=json.dumps(content).encode())
