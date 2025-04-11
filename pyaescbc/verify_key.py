import hmac
import hashlib
from .delete_bytearray import delete_bytearray
from .create_hmac import create_hmac

def verify_key(derived_key: bytearray, iv: bytearray, cipherdata: bytearray, expected_hmac: bytearray) -> bool:
    """
    Verifies if the derived 64-byte key matches the expected HMAC.

    Parameters
    ----------
    derived_key : bytearray
        The 64-byte derived key.

    iv : bytearray
        The 16-byte long initialization vector used for encryption.

    cipherdata : bytearray
        The encrypted message.

    expected_hmac : bytearray
        The expected 32-byte HMAC value.

    Returns
    -------
    bool
        True if the derived key matches the HMAC, False otherwise.

    Raises
    ------
    TypeError
        If any argument is not a `bytearray` instance.

    ValueError
        If the derived key isn't 64 bytes, the IV isn't 16 bytes, or the HMAC isn't 32 bytes.
    """
    if not isinstance(expected_hmac, bytearray):
        raise TypeError('Parameter expected_hmac is not bytearray instance.')

    if len(expected_hmac) != 32:
        raise ValueError(f'{expected_hmac=} is not 32 bytes long.')
    
    hmac_value = create_hmac(derived_key, iv, cipherdata)
    # Compare the computed HMAC with the expected one
    check = hmac.compare_digest(expected_hmac, hmac_value)
    
    # Securely delete the HMAC-related variables
    delete_bytearray(hmac_value)
    
    return check
