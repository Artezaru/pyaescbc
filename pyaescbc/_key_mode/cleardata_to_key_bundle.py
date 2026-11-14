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

from .._common.random import random_iv
from .._common.etm import encrypt_then_mac
from .._common.delete_bytearray import delete_bytearray
from .expand_key import expand_key
from .create_key_bundle import create_key_bundle_header, create_key_encrypted_bundle


def cleardata_to_key_bundle(
    cleardata: bytearray,
    key: bytearray,
    *,
    authdata: Optional[bytearray] = None,
    delete_keys: bool = False,
    delete_data: bool = True,
) -> bytearray:
    r"""
    Encrypts the clear data with a random key into a key-mode bundle (no key derivation).

    .. code-block:: text

        iv                = random
        aes_key, hmac_key = expand_key(key)                 (HKDF-Expand, no PBKDF2)
        cipherdata        = AES-256-CBC(aes_key, iv, cleardata)
        header            = magic "PACK" | version | iv
        hmac              = HMAC-SHA256(hmac_key, header, cipherdata, authdata)
        encrypted_bundle  = header | hmac | cipherdata

    The key mode is meant for envelope encryption: a random key (see
    ``pyaescbc.generate_key``) encrypts many small messages quickly, and the key itself
    is stored encrypted with a password using ``pyaescbc.encrypt``. Unlike
    ``pyaescbc.encrypt``, there is no key derivation: each call takes microseconds.

    .. warning::

        ``key`` must be uniformly random (from ``pyaescbc.generate_key``). **Never use a
        password as key**: it would be encrypted without any brute-force protection.
        Use ``pyaescbc.encrypt`` for passwords.

    .. note::

        An alias for this function is ``encrypt_with_key``.

        .. code-block:: python

            import pyaescbc

            key = pyaescbc.generate_key()
            cleardata = bytearray("Hello, World!", 'utf-8')
            authdata = bytearray("entry=42", 'utf-8')  # optional
            encrypted_bundle = pyaescbc.encrypt_with_key(cleardata, key, authdata=authdata)

    .. note::

        Memory wiping is best-effort: Python and the underlying libraries may keep
        immutable copies of sensitive data.

    Parameters
    ----------
    cleardata : bytearray
        The clear message to encrypt. It may be empty.

    key : bytearray
        The 32-byte random key.

    authdata : Optional[bytearray]
        Optional additional authenticated data (keyword-only). It is authenticated by the
        HMAC but neither encrypted nor stored in the bundle: the same value must be given
        for decryption. It is never modified by this function.

    delete_keys : bool
        Wipe the ``key`` at the end of the function, even if an error occurs.
        Default is False: a key-mode key is usually reused for many messages.

    delete_data : bool
        Wipe the ``cleardata`` at the end of the function, only if the encryption succeeded
        (the clear data is never destroyed when no encrypted bundle was produced).
        Default is True.

    Returns
    -------
    encrypted_bundle : bytearray
        The key-mode encrypted bundle.

    Raises
    ------
    TypeError
        If an argument is of the wrong type.
    ValueError
        If ``key`` is not 32 bytes long.
    """
    key_material = None
    success = False

    try:
        # Check the types of the parameters
        if not isinstance(cleardata, bytearray):
            raise TypeError('Parameter cleardata is not bytearray instance.')
        if not isinstance(key, bytearray):
            raise TypeError('Parameter key is not bytearray instance.')
        if authdata is not None and not isinstance(authdata, bytearray):
            raise TypeError('Parameter authdata is not bytearray instance.')
        if not isinstance(delete_keys, bool):
            raise TypeError('Parameter delete_keys is not a boolean.')
        if not isinstance(delete_data, bool):
            raise TypeError('Parameter delete_data is not a boolean.')

        # Public random parameter
        iv = random_iv()

        # Secret keys (the key length is checked by expand_key)
        key_material = expand_key(key)

        # Encrypt-then-MAC over the whole header (the sub-keys are wiped by encrypt_then_mac)
        header = create_key_bundle_header(iv)
        expected_hmac, cipherdata = encrypt_then_mac(cleardata, key_material, iv, header, authdata=authdata)
        encrypted_bundle = create_key_encrypted_bundle(header, expected_hmac, cipherdata)
        success = True
        return encrypted_bundle

    finally:
        # Secrets are always wiped
        if key_material is not None:
            delete_bytearray(key_material)
        if delete_keys:
            if isinstance(key, bytearray):
                delete_bytearray(key)
        # The clear data is only wiped once it is safely encrypted
        if delete_data and success:
            if isinstance(cleardata, bytearray):
                delete_bytearray(cleardata)
