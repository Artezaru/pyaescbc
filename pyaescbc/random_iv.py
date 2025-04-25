from .random_bytearray import random_bytearray

def random_iv() -> bytearray:
    """
    Generates a random 16-byte initialization vector (IV) for AES encryption.

    Returns
    -------
    iv : bytearray
        A random 16-byte bytearray to be used as an IV.
    """
    return random_bytearray(16)