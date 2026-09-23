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

from .derive_key import derive_key
from .decrypt_AES_CBC import decrypt_AES_CBC
from .extract_cryptography_components import extract_cryptography_components
from .check_hmac import check_hmac
from .create_hmac import create_hmac
from .delete_bytearray import delete_bytearray
from .auth_error import AuthError

def encrypted_bundle_to_cleardata(
    encrypted_bundle: bytearray,
    password: bytearray, 
    iterations: int,
    authdata: Optional[bytearray] = None,
    *,
    delete_keys: bool = True,
    delete_data: bool = True,
) -> bytearray: 
    """
    encrypted_bundle_to_cleardata decrypts the encrypted bundle to generate the cleardata.

    The number of iterations can be generated using the function :func:`pyaescbc.generate_random_iterations` or :func:`pyaescbc.generate_pin_iterations`.

    .. note::
        
        Use ``delete_data`` and ``delete_keys`` to deleted sensitive data 
        from memory at the end of the function.

    .. note::

        An alias for this function is ``decrypt``

        .. code-block:: python

            import pyaescbc as aes

            encrypted_bundle = bytearray(...) # The encrypted bundle
            password = bytearray(..., 'utf-8') # The user password used to encrypt the cipherdata and create the bundle
            iterations = ... # The number of iterations used to encrypt the cipherdata and create the bundle
            cleardata = aes.decrypt(encrypted_bundle, password, iterations, delete_keys=True, delete_data=True)
            # Or use : cleardata = aes.encrypted_bundle_to_cleardata(encrypted_bundle, password, iterations, delete_keys=True, delete_data=True)

    Parameters
    ----------
    encrypted_bundle : bytearray
        The encrypted bundle to decrypt using AES in CBC mode. Must contain at least 80 bytes.

    password : bytearray
        The user password. It must not be empty.

    iterations : int
        The number of iterations for PBKDF2. It must be a strictly positive integer.
    
    authdata : Optional[bytearray]
        The authentication data to use in the HMAC. Default is None.
        If not None, it will be used to create the HMAC.

    delete_keys : bool
        Delete the ``password`` from memory at the end of the function. Default is True.

    delete_data : bool
        Delete the ``encrypted_bundle`` from memory at the end of the function. Default is True.

    Returns
    -------
    cleardata : bytearray
        The decrypted message using AES in CBC mode.

    Raises
    ------
    TypeError
        If an argument is of the wrong type.
    ValueError
        If ``password`` is empty, ``iterations`` is not a strictly positive integer, or ``encrypted_bundle`` does not contain more than 80 bytes.
    """
    # Check the types of the parameters
    if (not isinstance(encrypted_bundle, bytearray)) or (not isinstance(password, bytearray)):
        raise TypeError("Parameters encrypted_bundle or password is not bytearray")
    if not isinstance(iterations, int):
        raise TypeError("Parameter iterations is not integer")
    if not isinstance(delete_keys, bool):
        raise ValueError("Parameter delete_keys is not a boolean.")
    if not isinstance(delete_data, bool):
        raise ValueError("Parameter delete_data is not a boolean.")

    # Check the values of the parameters
    if len(password) == 0:
        raise ValueError('Parameter password must not be empty.')
    if iterations <= 0:
        raise ValueError('Parameter iterations must be a positive integer.')
    if len(encrypted_bundle) < 80:
        raise ValueError(f'encrypted_bundle does not contain more than 80 bytes.')

    # Decryption
    salt = None
    iv = None
    derived_key = None
    aes_key = None
    hmac_key = None
    cipherdata = None
    expected_hmac = None
    try:
        iv, salt, expected_hmac, cipherdata = extract_cryptography_components(encrypted_bundle)
        derived_key = derive_key(password, salt, iterations)
        aes_key = derived_key[:32]  # AES key is the first 32 bytes of the derived key
        hmac_key = derived_key[32:]  # HMAC key is the last 32 bytes of the derived key
        given_hmac = create_hmac(hmac_key, iv, cipherdata, authdata=authdata)
        if not check_hmac(given_hmac, expected_hmac):
            raise AuthError('The HMAC is not valid. The data has been tampered with or the password is incorrect.')
        cleardata = decrypt_AES_CBC(cipherdata, aes_key, iv)
    except Exception as e:
        raise e
    finally:
        if delete_keys:
            delete_bytearray(password)
        if delete_data:
            delete_bytearray(encrypted_bundle)

        if derived_key is not None:
            delete_bytearray(derived_key)
        if aes_key is not None:
            delete_bytearray(aes_key)
        if hmac_key is not None:
            delete_bytearray(hmac_key)
        if authdata is not None:
            delete_bytearray(authdata)
        if salt is not None:
            delete_bytearray(salt)
        if iv is not None:
            delete_bytearray(iv)
        if cipherdata is not None:
            delete_bytearray(cipherdata)
        if expected_hmac is not None:
            delete_bytearray(expected_hmac)
        
    # Return the decrypted data
    return cleardata