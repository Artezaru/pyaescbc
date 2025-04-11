from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: bytearray, salt: bytearray, iterations: int) -> bytearray:
    """
    Derives a 48-byte key from a password using PBKDF2.

    The derived key is composed by the AES key and the HMAC key, both 32 bytes long.
    The AES key is used to encrypt the data using AES in CBC mode.
    The HMAC key is used to create the HMAC of the data.

    .. seealso::

        -function :func:`pyaescbc.generate_random_iterations` or :func:`pyaescbc.generate_pin_iterations` to generate the number of iterations.
        -function :func:`pyaescbc.encrypt_AES_CBC` to encrypt the data using AES in CBC mode.
        -function :func:`pyaescbc.create_hmac` to create the HMAC of the data.

    Parameters
    ----------
    password : bytearray
        The user password.

    salt : bytearray
        The 32-byte salt used to generate the derived key.

    iterations : int
        The number of iterations for PBKDF2.

    Returns
    -------
    derived_key : bytearray
        The derived 64-byte key.

    Raises
    ------
    TypeError
        If the arguments are not of the correct types.
    ValueError
        If `iterations` is not a positive integer.
    """
    if not isinstance(password, bytearray):
        raise TypeError('Parameter password is not bytearray instance.')
    if not isinstance(salt, bytearray):
        raise TypeError('Parameter salt is not bytearray instance.')
    if not isinstance(iterations, int):
        raise TypeError('Parameter iterations is not int instance.')

    if len(password) == 0:
        raise ValueError('Parameter password must not be empty.')
    if iterations <= 0:
        raise ValueError('Parameter iterations must be a positive integer.')
    if len(salt) != 32:
        raise ValueError(f'{salt=} is not 32 bytes long.') 

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=64,  # 32 bytes for AES + 32 bytes for HMAC
                     salt=bytes(salt),
                     iterations=iterations,
                     backend=default_backend())
    derived_key = bytearray(kdf.derive(password))
    return derived_key