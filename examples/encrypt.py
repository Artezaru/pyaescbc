import pyaescbc

# Encryption
cleardata = bytearray("Hello, World!", 'utf-8')
pin = bytearray("1234", 'utf-8')
password = bytearray("password", 'utf-8')
iterations = pyaescbc.generate_pin_iterations(pin, delete_keys=True)
authdata = bytearray("user=toto", 'utf-8') # Optional authentication data (can be None)
encrypted_bundle = pyaescbc.encrypt(cleardata, password, iterations, authdata=authdata, delete_keys=True)

# Decryption
pin = bytearray("1234", 'utf-8')
password = bytearray("password", 'utf-8')
iterations = pyaescbc.generate_pin_iterations(pin, delete_keys=True)
authdata = bytearray("user=toto", 'utf-8') # Optional authentication data (can be None)
decrypted_data = pyaescbc.decrypt(encrypted_bundle, password, iterations, authdata=authdata, delete_keys=True)

print(decrypted_data)
