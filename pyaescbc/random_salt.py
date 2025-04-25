from .random_bytearray import random_bytearray

def random_salt() -> bytearray:
    """
    Generates a random 32-byte salt for cryptographic purposes.

    Returns
    -------
    salt : bytearray
        A random 32-byte bytearray to be used as a salt.
    """
    return random_bytearray(32)