import pyaescbc
import pytest

def test_iteration_from_pin():
    pin = bytearray("1234", 'utf-8')
    iterations = pyaescbc.generate_pin_iterations(pin)
    assert iterations > 0

def test_encrypt_decrypt():
    """ Test the encryption and decryption of a message. """
    cleardata = bytearray("Hello, World!", 'utf-8')
    cleardata_copy = cleardata.copy()
    pin = bytearray("1234", 'utf-8')
    password = bytearray("password", 'utf-8')
    iterations = pyaescbc.generate_pin_iterations(pin, delete_keys=True)
    encrypted_bundle = pyaescbc.encrypt(cleardata, password, iterations, delete_keys=True)

    assert len(cleardata) == 0 # The data is deleted.
    assert len(password) == 0 # The password is deleted.

    password = bytearray("password", 'utf-8')
    pin = bytearray("1234", 'utf-8')
    iterations = pyaescbc.generate_pin_iterations(pin, delete_keys=True)
    cleardata = pyaescbc.decrypt(encrypted_bundle, password, iterations, delete_keys=True)

    assert cleardata == cleardata_copy
