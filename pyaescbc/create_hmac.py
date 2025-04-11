import hmac
import hashlib
from .delete_bytearray import delete_bytearray

def create_hmac(derived_key: bytearray, iv: bytearray, cipherdata: bytearray) -> bytearray:
    """
    Creates the expected HMAC value from the derived key, IV, and cipherdata.

    The HMAC allows the receiver to verify the integrity of the encrypted message.

    .. seealso::

        -function :func:`pyaescbc.derive_key` to create the derived key.

    Parameters
    ----------
    derived_key : bytearray
        The 64-byte derived key.

    iv : bytearray
        The 16-byte long initialization vector used for encryption.

    cipherdata : bytearray
        The encrypted message.

    Returns
    -------
    expected_hmac : bytearray
        The 32-byte expected HMAC value.

    Raises
    ------
    TypeError
        If any argument is not a `bytearray` instance.

    ValueError
        If the derived key isn't 64 bytes or the IV isn't 16 bytes.
    """
    if not isinstance(derived_key, bytearray):
        raise TypeError('Parameter derived_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')
    if not isinstance(cipherdata, bytearray):
        raise TypeError('Parameter cipherdata is not bytearray instance.')
        
    if len(derived_key) != 64:
        raise ValueError(f'{derived_key=} is not 64 bytes long.') 
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.')

    hmac_key = derived_key[32:]
    expected_hmac = bytearray(hmac.new(hmac_key, iv + cipherdata, hashlib.sha256).digest())
    # Securely delete the hmac_key
    delete_bytearray(hmac_key)
    return expected_hmac
