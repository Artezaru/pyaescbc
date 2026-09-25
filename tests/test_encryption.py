import pyaescbc
import pytest


def test_encrypt_decrypt():
    """Test the encryption and decryption of a message."""
    cleardata = bytearray("Hello, World!", "utf-8")
    cleardata_copy = cleardata.copy()
    password = bytearray("password", "utf-8")
    iterations = 800_000
    encrypted_bundle = pyaescbc.encrypt(
        cleardata, password, iterations=iterations, delete_keys=True, delete_data=True
    )

    assert len(cleardata) == 0  # The data is deleted.
    assert len(password) == 0  # The password is deleted.

    password = bytearray("password", "utf-8")
    cleardata = pyaescbc.decrypt(encrypted_bundle, password, delete_keys=True)

    assert cleardata == cleardata_copy
