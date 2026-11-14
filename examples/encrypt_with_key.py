"""
Key mode: encrypt many secrets with a random key ("envelope encryption").

A random data key encrypts each secret without any key derivation (microseconds per call).
The data key itself is protected once with a password, using the password mode.

Run from the repository root:  python examples/encrypt_with_key.py
"""
import os
import sys

# Use the pyaescbc of this repository rather than an installed one
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyaescbc

# --- Creation (once) --------------------------------------------------------
# Random data key, wrapped with the password: one slow key derivation.
data_key = pyaescbc.generate_key()  # 32 random bytes. NEVER use a password as key.
wrapped_key = pyaescbc.encrypt(data_key.copy(), bytearray("password", "utf-8"))

# Each secret is encrypted with the data key: fast, no key derivation.
# authdata binds each secret to its entry, so it cannot be swapped with another one.
entries = {"github": "gh-p4ssw0rd", "mail": "m41l-s3cr3t", "bank": "b4nk-c0de"}
vault = {
    name: pyaescbc.encrypt_with_key(
        bytearray(secret, "utf-8"),
        data_key,                                  # kept: reused for every secret
        authdata=bytearray(f"entry={name}", "utf-8"),
    )
    for name, secret in entries.items()
}
pyaescbc.delete_bytearray(data_key)  # end of the session

# --- Next session -----------------------------------------------------------
# One slow derivation to unwrap the data key, then every secret decrypts quickly.
data_key = pyaescbc.decrypt(wrapped_key, bytearray("password", "utf-8"))

for name, bundle in vault.items():
    secret = pyaescbc.decrypt_with_key(bundle, data_key, authdata=bytearray(f"entry={name}", "utf-8"))
    print(f"{name}: {secret.decode('utf-8')}")
    pyaescbc.delete_bytearray(secret)

# A secret moved to another entry is detected
try:
    pyaescbc.decrypt_with_key(vault["github"], data_key, authdata=bytearray("entry=bank", "utf-8"))
except pyaescbc.AuthError:
    print("Swapped entries detected.")
    print("This failed as expected.")

# --- Password change --------------------------------------------------------
# Only the data key is re-wrapped: the secrets are not re-encrypted.
wrapped_key = pyaescbc.encrypt(data_key.copy(), bytearray("new password", "utf-8"))

pyaescbc.delete_bytearray(data_key)  # end of the session