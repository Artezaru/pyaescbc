from .random_bytearray import random_bytearray
from .derive_key import derive_key
from .decrypt_AES_CBC import decrypt_AES_CBC
from .extract_cryptography_components import extract_cryptography_components
from .verify_key import verify_key
from .delete_bytearray import delete_bytearray
from .wrong_key_error import WrongKeyError

def encrypted_bundle_to_cleardata(
    encrypted_bundle: bytearray,
    password: bytearray, 
    iterations: int,
    delete_keys: bool = True
) -> bytearray: 
    """
    encrypted_bundle_to_cleardata decrypts the encrypted bundle to generate the cleardata.

    The number of iterations can be generated using the function :func:`pyaescbc.generate_random_iterations` or :func:`pyaescbc.generate_pin_iterations`.

    .. note::
        
        The encrypted_bundle and the password are deleted from memory at the end of the function if delete_keys is True.
        Otherwise, they need to be deleted after dealing with Exception.

    .. note::

        An alias for this function is ``decrypt``

        .. code-block:: python

            import pyaescbc as aes

            encrypted_bundle = bytearray(...) # The encrypted bundle
            password = bytearray(..., 'utf-8') # The user password used to encrypt the cipherdata and create the bundle
            iterations = ... # The number of iterations used to encrypt the cipherdata and create the bundle
            cleardata = aes.decrypt(encrypted_bundle, password, iterations, delete_keys=True)
            # Or use : cleardata = aes.encrypted_bundle_to_cleardata(encrypted_bundle, password, iterations, delete_keys=True)

    Parameters
    ----------
    encrypted_bundle : bytearray
        The encrypted bundle to decrypt using AES in CBC mode. Must contain at least 80 bytes.

    password : bytearray
        The user password.

    iterations : int
        The number of iterations for PBKDF2.

    delete_keys : bool
        Delete the cleardata, the password from memory at the end of the function. Default is True.

    Returns
    -------
    cleardata : bytearray
        The decrypted message using AES in CBC mode.

    Raises
    ------
    TypeError
        If an argument is of the wrong type.
    ValueError
        If Nmin or Nmax are not positive integers or if Nmin is greater than Nmax.
    """
    if (not isinstance(encrypted_bundle, bytearray)) or (not isinstance(password, bytearray)):
        raise TypeError("Parameters encrypted_bundle or password is not bytearray")
    if not isinstance(iterations, int):
        raise TypeError("Parameter iterations is not integer")
    if not isinstance(delete_keys, bool):
        raise ValueError("Parameter delete_keys is not a boolean.")

    if len(encrypted_bundle) < 80:
        raise ValueError(f'encrypted_bundle does not contain more than 80 bytes.')

    # Decryption
    iv, salt, expected_hmac, cipherdata = extract_cryptography_components(encrypted_bundle)
    derived_key = derive_key(password, salt, iterations)
    if not verify_key(derived_key, iv, cipherdata, expected_hmac):
        # Deleting from memory all critical data for security
        if delete_keys:
            delete_bytearray(password)
            delete_bytearray(encrypted_bundle)
        delete_bytearray(derived_key)
        delete_bytearray(iv)
        delete_bytearray(salt)
        delete_bytearray(expected_hmac)
        delete_bytearray(cipherdata)
        raise WrongKeyError("WARNING: password can't decrypt the encrypted_bundle")

    cleardata = decrypt_AES_CBC(cipherdata, derived_key, iv)

    # Deleting from memory all critical data for security
    if delete_keys:
        delete_bytearray(password)
        delete_bytearray(encrypted_bundle)
    delete_bytearray(derived_key)
    delete_bytearray(iv)
    delete_bytearray(salt)
    delete_bytearray(expected_hmac)
    delete_bytearray(cipherdata)

    return cleardata
