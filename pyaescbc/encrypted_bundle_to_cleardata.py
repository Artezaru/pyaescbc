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
    *,
    authdata: Optional[bytearray] = None,
    delete_keys: bool = True,
    delete_data: bool = False,
) -> bytearray:
    r"""
    Decrypts an encrypted bundle (format version 2) and returns the clear data.

    .. code-block:: text

        header | hmac | cipherdata = encrypted_bundle     (structure checked first)
        aes_key, hmac_key          = derive_key(password, salt, iterations)
        check  HMAC-SHA256(hmac_key, header, cipherdata, authdata) == hmac   (constant time)
        cleardata                  = AES-256-CBC-decrypt(aes_key, iv, cipherdata)

    The number of iterations is read from the bundle. The cipherdata is decrypted only
    after the HMAC has been verified.

    .. note::

        An alias for this function is ``decrypt``.

        .. code-block:: python

            import pyaescbc

            password = bytearray("password", 'utf-8')
            authdata = bytearray("user=toto", 'utf-8')  # same value as for encryption
            cleardata = pyaescbc.decrypt(encrypted_bundle, password, authdata)

    .. note::

        Memory wiping is best-effort: Python and the underlying libraries may keep
        immutable copies of sensitive data.

    Parameters
    ----------
    encrypted_bundle : bytearray
        The encrypted bundle created by :func:`pyaescbc.encrypt`.

    password : bytearray
        The user password. It must not be empty.

    authdata : Optional[bytearray]
        The additional authenticated data given at encryption (``None`` if none was given).
        It is never modified by this function.

    delete_keys : bool
        Wipe the ``password`` at the end of the function, even if an error occurs.
        Default is True.

    delete_data : bool
        Wipe the ``encrypted_bundle`` at the end of the function, only if the decryption
        succeeded (the bundle is never destroyed after a failed attempt, e.g. a mistyped
        password). Default is False: the bundle is not secret.

    Returns
    -------
    cleardata : bytearray
        The decrypted clear data.

    Raises
    ------
    TypeError
        If an argument is of the wrong type.
    ValueError
        If ``password`` is empty or the bundle is malformed (unknown format or version,
        invalid length, iterations out of range).
    AuthError
        If the password or the authdata is wrong, or if the bundle has been tampered with.
    """
    # Check the types of the parameters
    if not isinstance(encrypted_bundle, bytearray):
        raise TypeError('Parameter encrypted_bundle is not bytearray instance.')
    if not isinstance(password, bytearray):
        raise TypeError('Parameter password is not bytearray instance.')
    if authdata is not None and not isinstance(authdata, bytearray):
        raise TypeError('Parameter authdata is not bytearray instance.')
    if not isinstance(delete_keys, bool):
        raise TypeError('Parameter delete_keys is not a boolean.')
    if not isinstance(delete_data, bool):
        raise TypeError('Parameter delete_data is not a boolean.')

    derived_key = None
    aes_key = None
    hmac_key = None
    success = False
    try:
        components = extract_cryptography_components(encrypted_bundle)

        derived_key = derive_key(password, components.salt, components.iterations)
        aes_key = derived_key[:32]
        hmac_key = derived_key[32:]

        computed_hmac = create_hmac(hmac_key, components.header, components.cipherdata, authdata)
        if not check_hmac(computed_hmac, components.expected_hmac):
            raise AuthError('Authentication failed: wrong password or authdata, or the data has been tampered with.')

        # Decrypt only authenticated data
        cleardata = decrypt_AES_CBC(components.cipherdata, aes_key, components.iv)
        success = True
        return cleardata

    finally:
        # Secrets are always wiped
        for secret in (derived_key, aes_key, hmac_key):
            if secret is not None:
                delete_bytearray(secret)
        if delete_keys:
            delete_bytearray(password)
        # The bundle is only wiped once it has been successfully decrypted
        if delete_data and success:
            delete_bytearray(encrypted_bundle)