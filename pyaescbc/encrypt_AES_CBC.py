from cryptography.hazmat.primitives import padding, ciphers
from cryptography.hazmat.backends import default_backend

def encrypt_AES_CBC(cleardata: bytearray, derived_key: bytearray, iv: bytearray) -> bytearray:
    r"""
    Encrypts a cleardata message using AES in CBC mode.

    The cleardata is padded using PKCS7 padding and then encrypted using AES in CBC mode.
    The derived key is composed of the AES key and the HMAC key, both 32 bytes long.

    .. seealso::
        function :func:`pyaescbc.derive_key` to create the derived key.

    .. note::
        The cleardata, derived_key and iv must be bytearrays.

    Parameters
    ----------
    cleardata : bytearray
        The message to encrypt using AES in CBC mode.

    derived_key : bytearray
        The 64-byte derived key extracted from the password and salt.
        The first 32 bytes are the AES key.

    iv : bytearray
        The initialization vector (IV) to use in AES-CBC mode.
        Must be 16 bytes long.

    Returns
    -------
    cipherdata: bytearray
        The encrypted message.

    Raises
    ------
    TypeError
        If a given argument is not a `bytearray` instance.
    ValueError
        If the `derived_key` isn't 64 bytes long or the `iv` isn't 16 bytes long.
    """
    if not isinstance(cleardata, bytearray):
        raise TypeError('Parameter cleardata is not bytearray instance.')
    if not isinstance(derived_key, bytearray):
        raise TypeError('Parameter derived_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')

    if len(derived_key) != 64:
        raise ValueError(f'{derived_key=} is not 64 bytes long.') 
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.')
    
    padder = padding.PKCS7(128).padder()  
    cipher = ciphers.Cipher(ciphers.algorithms.AES(derived_key[:32]), ciphers.modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = padder.update(cleardata) + padder.finalize()
    cipherdata = bytearray(encryptor.update(padded_data) + encryptor.finalize())
    return cipherdata
