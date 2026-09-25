

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import pyaescbc

# Encryption
cleardata = bytearray("Hello, World!", 'utf-8')
password = bytearray("password", 'utf-8')
iterations = 2_000_000
authdata = bytearray("user=toto", 'utf-8') # Optional authentication data (can be None)
encrypted_bundle = pyaescbc.encrypt(cleardata, password, iterations=iterations, authdata=authdata, delete_keys=True, delete_data=True)

# Decryption
password = bytearray("password", 'utf-8')
iterations = 2_000_000
authdata = bytearray("user=toto", 'utf-8') # Optional authentication data (can be None)
decrypted_data = pyaescbc.decrypt(encrypted_bundle, password, authdata=authdata, delete_keys=True)

print(decrypted_data)
