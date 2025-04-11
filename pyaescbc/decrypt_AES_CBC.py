from cryptography.hazmat.primitives import padding, ciphers
from cryptography.hazmat.backends import default_backend

def decrypt_AES_CBC(cipherdata: bytearray, derived_key: bytearray, iv: bytearray) -> bytearray:
    """
    Decrypts a cipherdata message using AES in CBC mode.

    The data is unpadded using PKCS7 padding and then decrypted using AES in CBC mode.
    The derived key is composed of the AES key and the HMAC key, both 32 bytes long.

    .. seealso::
        function :func:`pyaescbc.derive_key` to create the derived key.

    .. note::
        The cipherdata, derived_key and iv must be bytearrays.

    Parameters
    ----------
    cipherdata : bytearray
        The encrypted message to decrypt using AES in CBC mode.

    derived_key : bytearray
        The 64-byte derived key extracted from the password and salt.
        The first 32 bytes are the AES key.

    iv : bytearray
        The initialization vector (IV) to use in AES-CBC mode.
        Must be 16 bytes long.

    Returns
    -------
    cleardata : bytearray
        The decrypted clear message.

    Raises
    ------
    TypeError
        If a given argument is not a `bytearray` instance.
    ValueError
        If the `derived_key` isn't 64 bytes long or the `iv` isn't 16 bytes long.
    """
    if not isinstance(cipherdata, bytearray):
        raise TypeError('Parameter cipherdata is not bytearray instance.')
    if not isinstance(derived_key, bytearray):
        raise TypeError('Parameter derived_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')

    if len(derived_key) != 64:
        raise ValueError(f'{derived_key=} is not 64 bytes long.') 
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.')
    
    cipher = ciphers.Cipher(ciphers.algorithms.AES(derived_key[:32]), ciphers.modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()  
    decrypted_data = decryptor.update(cipherdata) + decryptor.finalize() 
    unpadded_data = bytearray(unpadder.update(decrypted_data) + unpadder.finalize())

    # Returning the decrypted clear data
    return unpadded_data
