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
from .create_encrypted_bundle import create_bundle_header, create_encrypted_bundle
from .delete_bytearray import delete_bytearray

#: Default number of PBKDF2 iterations (OWASP recommendation for PBKDF2-HMAC-SHA256).
DEFAULT_ITERATIONS = 600_000

def cleardata_to_encrypted_bundle(
    cleardata: bytearray,
    password: bytearray,
    *,
    authdata: Optional[bytearray] = None,
    iterations: int = DEFAULT_ITERATIONS,
    delete_keys: bool = True,
    delete_data: bool = True,
) -> bytearray:
    r"""
    Encrypts the clear data into an encrypted bundle (format version 2).

    .. code-block:: text

        salt, iv          = random
        aes_key, hmac_key = derive_key(password, salt, iterations)
        cipherdata        = AES-256-CBC(aes_key, iv, cleardata)
        header            = magic | version | iterations | salt | iv
        hmac              = HMAC-SHA256(hmac_key, header, cipherdata, authdata)
        encrypted_bundle  = header | hmac | cipherdata

    The number of iterations is stored in the bundle: it is not needed for decryption.

    .. note::

        An alias for this function is ``encrypt``.

        .. code-block:: python

            import pyaescbc

            cleardata = bytearray("Hello, World!", 'utf-8')
            password = bytearray("password", 'utf-8')
            authdata = bytearray("user=toto", 'utf-8')  # optional
            encrypted_bundle = pyaescbc.encrypt(cleardata, password, authdata)

    .. note::

        Memory wiping is best-effort: Python and the underlying libraries may keep
        immutable copies of sensitive data.

    Parameters
    ----------
    cleardata : bytearray
        The clear message to encrypt.

    password : bytearray
        The user password. It must not be empty.

    authdata : Optional[bytearray]
        Optional additional authenticated data. It is authenticated by the HMAC but neither
        encrypted nor stored in the bundle: the same value must be given for decryption.
        It is never modified by this function.

    iterations : int
        The number of PBKDF2 iterations (keyword-only). Default is 600 000.
        Must be between 100 000 and 10 000 000.

    delete_keys : bool
        Wipe the ``password`` at the end of the function, even if an error occurs.
        Default is True.

    delete_data : bool
        Wipe the ``cleardata`` at the end of the function, only if the encryption succeeded
        (the clear data is never destroyed when no encrypted bundle was produced).
        Default is True.

    Returns
    -------
    encrypted_bundle : bytearray
        The encrypted bundle.

    Raises
    ------
    TypeError
        If an argument is of the wrong type.
    ValueError
        If ``password`` is empty or ``iterations`` is out of the allowed range.
    """
    # Check the types of the parameters
    if not isinstance(cleardata, bytearray):
        raise TypeError('Parameter cleardata is not bytearray instance.')
    if not isinstance(password, bytearray):
        raise TypeError('Parameter password is not bytearray instance.')
    if authdata is not None and not isinstance(authdata, bytearray):
        raise TypeError('Parameter authdata is not bytearray instance.')
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise TypeError('Parameter iterations is not int instance.')
    if not isinstance(delete_keys, bool):
        raise TypeError('Parameter delete_keys is not a boolean.')
    if not isinstance(delete_data, bool):
        raise TypeError('Parameter delete_data is not a boolean.')

    derived_key = None
    aes_key = None
    hmac_key = None
    success = False
    try:
        # Public random parameters
        salt = random_salt()
        iv = random_iv()

        # Secret keys (bounds on iterations and password are checked by derive_key)
        derived_key = derive_key(password, salt, iterations)
        aes_key = derived_key[:32]
        hmac_key = derived_key[32:]

        # Encrypt-then-MAC over the whole header
        cipherdata = encrypt_AES_CBC(cleardata, aes_key, iv)
        header = create_bundle_header(iterations, salt, iv)
        expected_hmac = create_hmac(hmac_key, header, cipherdata, authdata)
        encrypted_bundle = create_encrypted_bundle(header, expected_hmac, cipherdata)
        success = True
        return encrypted_bundle

    finally:
        # Secrets are always wiped
        for secret in (derived_key, aes_key, hmac_key):
            if secret is not None:
                delete_bytearray(secret)
        if delete_keys:
            delete_bytearray(password)
        # The clear data is only wiped once it is safely encrypted
        if delete_data and success:
            delete_bytearray(cleardata)