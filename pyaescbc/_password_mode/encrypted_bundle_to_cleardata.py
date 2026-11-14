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

from .._common.etm import verify_then_decrypt
from .._common.delete_bytearray import delete_bytearray
from .derive_key import derive_key
from .extract_cryptography_components import extract_cryptography_components

_AUTH_ERROR_MESSAGE = 'Authentication failed: wrong password or authdata, or the data has been tampered with.'


def encrypted_bundle_to_cleardata(
    encrypted_bundle: bytearray,
    password: bytearray,
    *,
    authdata: Optional[bytearray] = None,
    delete_keys: bool = True,
    delete_data: bool = False,
) -> bytearray:
    r"""
    Decrypts a password-mode bundle (format version 2) and returns the clear data.

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
            cleardata = pyaescbc.decrypt(encrypted_bundle, password, authdata=authdata)

    .. note::

        Memory wiping is best-effort: Python and the underlying libraries may keep
        immutable copies of sensitive data.

    Parameters
    ----------
    encrypted_bundle : bytearray
        The password-mode bundle created by ``pyaescbc.encrypt``.

    password : bytearray
        The user password. It must not be empty.

    authdata : Optional[bytearray]
        The additional authenticated data given at encryption, keyword-only (``None`` if none was given).
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
    derived_key = None
    success = False

    try:
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

        # Structure checked BEFORE the (slow) key derivation
        components = extract_cryptography_components(encrypted_bundle)

        derived_key = derive_key(password, components.salt, components.iterations)

        # HMAC verified in constant time, then decryption of authenticated data only
        # (the sub-keys are wiped by verify_then_decrypt)
        cleardata = verify_then_decrypt(
            components.header,
            components.expected_hmac,
            components.cipherdata,
            derived_key,
            components.iv,
            authdata=authdata,
            error_message=_AUTH_ERROR_MESSAGE,
        )
        success = True
        return cleardata

    finally:
        # Secrets are always wiped
        if derived_key is not None:
            delete_bytearray(derived_key)
        if delete_keys:
            if isinstance(password, bytearray):
                delete_bytearray(password)
        # The bundle is only wiped once it has been successfully decrypted
        if delete_data and success:
            if isinstance(encrypted_bundle, bytearray):
                delete_bytearray(encrypted_bundle)