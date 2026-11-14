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

from .._common.random import random_salt, random_iv
from .._common.etm import encrypt_then_mac
from .._common.delete_bytearray import delete_bytearray
from .derive_key import derive_key
from .create_encrypted_bundle import create_bundle_header, create_encrypted_bundle

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
    Encrypts the clear data with a password into a password-mode bundle (format version 2).

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
            encrypted_bundle = pyaescbc.encrypt(cleardata, password, authdata=authdata)

    .. note::

        Memory wiping is best-effort: Python and the underlying libraries may keep
        immutable copies of sensitive data.

    Parameters
    ----------
    cleardata : bytearray
        The clear message to encrypt. It may be empty.

    password : bytearray
        The user password. It must not be empty.

    authdata : Optional[bytearray]
        Optional additional authenticated data (keyword-only). It is authenticated by the HMAC but neither
        encrypted nor stored in the bundle: the same value must be given for decryption.
        It is never modified by this function.

    iterations : int
        The number of PBKDF2 iterations (keyword-only). Default is 600 000.
        Must be between 100 000 and 100 000 000.

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
    derived_key = None
    success = False

    try:
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

        # Public random parameters
        salt = random_salt()
        iv = random_iv()

        # Secret keys (bounds on iterations and password are checked by derive_key)
        derived_key = derive_key(password, salt, iterations)

        # Encrypt-then-MAC over the whole header (the sub-keys are wiped by encrypt_then_mac)
        header = create_bundle_header(iterations, salt, iv)
        expected_hmac, cipherdata = encrypt_then_mac(cleardata, derived_key, iv, header, authdata=authdata)
        encrypted_bundle = create_encrypted_bundle(header, expected_hmac, cipherdata)
        success = True
        return encrypted_bundle

    finally:
        # Secrets are always wiped
        if derived_key is not None:
            delete_bytearray(derived_key)
        if delete_keys:
            if isinstance(password, bytearray):
                delete_bytearray(password)
        # The clear data is only wiped once it is safely encrypted
        if delete_data and success:
            if isinstance(cleardata, bytearray):
                delete_bytearray(cleardata)