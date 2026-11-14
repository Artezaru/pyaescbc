"""
Password mode: encrypt and decrypt data with a password.

The key is derived from the password with PBKDF2 (slow on purpose, to resist brute-force
attacks). To encrypt many secrets, see encrypt_with_key.py.

Run from the repository root:  python examples/encrypt.py
"""
import os
import sys

# Use the pyaescbc of this repository rather than an installed one
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyaescbc

# --- Encryption -------------------------------------------------------------
cleardata = bytearray("Hello, World!", "utf-8")
password = bytearray("password", "utf-8")
authdata = bytearray("user=toto", "utf-8")  # optional additional authenticated data (can be None)

encrypted_bundle = pyaescbc.encrypt(
    cleardata,
    password,
    authdata=authdata,
    iterations=2_000_000,  # stored in the bundle: not needed to decrypt
    delete_keys=True,      # wipe the password (default)
    delete_data=True,      # wipe the clear data once encrypted (default)
)
assert len(cleardata) == 0 and len(password) == 0  # both wiped

# --- Decryption -------------------------------------------------------------
password = bytearray("password", "utf-8")
authdata = bytearray("user=toto", "utf-8")  # same value as for encryption

decrypted_data = pyaescbc.decrypt(encrypted_bundle, password, authdata=authdata, delete_keys=True)
print(decrypted_data)  # bytearray(b'Hello, World!')

# --- Wrong password ---------------------------------------------------------
try:
    pyaescbc.decrypt(encrypted_bundle, bytearray("wrong password", "utf-8"), authdata=authdata)
except pyaescbc.AuthError:
    print("Wrong password or authdata, or tampered data.")
    print("This failed as expected.")