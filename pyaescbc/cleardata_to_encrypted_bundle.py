from .random_bytearray import random_bytearray
from .derive_key import derive_key
from .encrypt_AES_CBC import encrypt_AES_CBC
from .create_hmac import create_hmac
from .create_encrypted_bundle import create_encrypted_bundle
from .delete_bytearray import delete_bytearray

def cleardata_to_encrypted_bundle(
    cleardata: bytearray, 
    password: bytearray, 
    iterations: int,
    delete_keys: bool = True
) -> bytearray: 
    """
    cleardata_to_encrypted_bundle encrypts the clear data to generate the encrypted bundle.

    The number of iterations can be generated using the function :func:`pyaescbc.generate_random_iterations` or :func:`pyaescbc.generate_pin_iterations`.

    .. note::
        
        The cleardata and the password are deleted from memory at the end of the function if delete_keys is True.
        Otherwise, they need to be deleted after dealing with Exception.

    .. note::

        An alias for this function is ``encrypt``

        .. code-block:: python

            import pyaescbc as aes

            cleardata = bytearray("Hello, World!", 'utf-8')
            password = bytearray("password", 'utf-8')
            iterations = aes.generate_random_iterations()
            encrypted_bundle = aes.encrypt(cleardata, password, iterations, delete_keys=True)
            # Or use : encrypted_bundle = aes.cleardata_to_encrypted_bundle(cleardata, password, iterations, delete_keys=True)

    Parameters
    ----------
    cleardata : bytearray
        The clear message to encrypt using AES in CBC mode.

    password : bytearray
        The user password.

    iterations : int
        The number of iterations for PBKDF2.

    delete_keys : bool
        Delete the cleardata, the password from memory at the end of the function. Default is True.

    Returns
    -------
    encrypted_bundle : bytearray
        The encrypted bundle. 

    Raises
    ------
    TypeError
        If an argument is of the wrong type.
    ValueError
        If Nmin or Nmax are not positive integers or if Nmin is greater than Nmax.
    """
    if (not isinstance(cleardata, bytearray)) or (not isinstance(password, bytearray)):
        raise TypeError("Parameters cleardata or password is not bytearray")
    if not isinstance(iterations, int):
        raise TypeError("Parameter iterations is not integer")
    if not isinstance(delete_keys, bool):
        raise ValueError("Parameter delete_keys is not a boolean.")

    # Encryption
    salt = random_bytearray(32)
    iv = random_bytearray(16)
    derived_key = derive_key(password, salt, iterations)
    cipherdata = encrypt_AES_CBC(cleardata, derived_key, iv)
    expected_hmac = create_hmac(derived_key, iv, cipherdata)
    encrypted_bundle = create_encrypted_bundle(iv, salt, expected_hmac, cipherdata)

    # Deleting from memory all critical data for security
    if delete_keys:
        delete_bytearray(password)
        delete_bytearray(cleardata)
    delete_bytearray(salt)
    delete_bytearray(iv)
    delete_bytearray(cipherdata)
    delete_bytearray(derived_key)

    return encrypted_bundle
