# Copyright 2025 Artezaru
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Optional

from .random_salt import random_salt
from .random_iv import random_iv
from .derive_key import derive_key
from .encrypt_AES_CBC import encrypt_AES_CBC
from .create_hmac import create_hmac
from .create_encrypted_bundle import create_encrypted_bundle
from .delete_bytearray import delete_bytearray

def cleardata_to_encrypted_bundle(
    cleardata: bytearray, 
    password: bytearray, 
    iterations: int,
    authdata: Optional[bytearray] = None,
    delete_keys: bool = True
) -> bytearray: 
    """
    cleardata_to_encrypted_bundle encrypts the clear data to generate the encrypted bundle.

    The number of iterations can be generated using the function :func:`pyaescbc.generate_random_iterations` or :func:`pyaescbc.generate_pin_iterations`.

    .. note::
        
        The cleardata, the password and the authdata are deleted from memory at the end of the function if delete_keys is True.
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
        The user password. It must not be empty.

    iterations : int
        The number of iterations for PBKDF2. It must be a strictly positive integer.

    authdata : Optional[bytearray]
        The authentication data to use in the HMAC. Default is None.
        If not None, it will be used to create the HMAC. 

    delete_keys : bool
        Delete the cleardata, the password and authdata from memory at the end of the function. Default is True.

    Returns
    -------
    encrypted_bundle : bytearray
        The encrypted bundle. 

    Raises
    ------
    TypeError
        If an argument is of the wrong type.
    ValueError
        If password is empty or if iterations is not a strictly positive integer.
    """
    # Check the types of the parameters
    if (not isinstance(cleardata, bytearray)) or (not isinstance(password, bytearray)):
        raise TypeError("Parameters cleardata or password is not bytearray")
    if not isinstance(iterations, int):
        raise TypeError("Parameter iterations is not integer")
    if (authdata is not None) and (not isinstance(authdata, bytearray)):
        raise TypeError("Parameter authdata is not bytearray")
    if not isinstance(delete_keys, bool):
        raise TypeError("Parameter delete_keys is not a boolean.")

    # Encryption
    try:
        salt = random_salt()
        iv = random_iv()
        derived_key = derive_key(password, salt, iterations)
        aes_key = derived_key[:32]  # AES key is the first 32 bytes of the derived key
        hmac_key = derived_key[32:]  # HMAC key is the last 32 bytes of the derived key
        cipherdata = encrypt_AES_CBC(cleardata, aes_key, iv)
        expected_hmac = create_hmac(hmac_key, iv, cipherdata, authdata=authdata)
        encrypted_bundle = create_encrypted_bundle(iv, salt, expected_hmac, cipherdata)
    except Exception as e:
        raise e
    finally:
        # Deleting from memory all critical data for security (in the order of their creation to avoid memory leaks)
        if delete_keys:
            delete_bytearray(cleardata)
            delete_bytearray(password)
            if authdata is not None:
                delete_bytearray(authdata)
        delete_bytearray(salt)
        delete_bytearray(iv)
        delete_bytearray(derived_key)
        delete_bytearray(aes_key)
        delete_bytearray(hmac_key)
        delete_bytearray(cipherdata)
        delete_bytearray(expected_hmac)

    # Return the encrypted bundle
    return encrypted_bundle
