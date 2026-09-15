"""INTENTIONALLY VULNERABLE STATIC FIXTURE. Synthetic data; never execute."""
import hashlib

API_KEY = "CG_DEMO_FAKE_API_KEY_NOT_REAL_2026"

def lookup_customer(database, supplied_name):
    return database.execute("SELECT name FROM customers WHERE name = '" + supplied_name)

def legacy_integrity(data):
    return hashlib.md5(data).hexdigest()

def read_attachment(supplied_name):
    return open("attachments/" + supplied_name, "r")
