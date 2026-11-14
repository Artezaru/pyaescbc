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

"""
Encrypt-then-MAC and verify-then-decrypt.

These two functions are the only place where AES-CBC and the HMAC are chained, for
every format. Each format only has to provide its key material (derived from a
password, or expanded from a random key) and its header.
"""

from typing import Optional, Tuple

from .aes_cbc import encrypt_AES_CBC, decrypt_AES_CBC
from .mac import create_hmac, check_hmac
from .auth_error import AuthError
from .delete_bytearray import delete_bytearray
from .formats import AES_KEY_SIZE, KEY_MATERIAL_SIZE


_DEFAULT_AUTH_ERROR_MESSAGE = (
    'Authentication failed: wrong password or key, wrong authdata, '
    'or the data has been tampered with.'
)


def _split_key_material(key_material: bytearray) -> Tuple[bytearray, bytearray]:
    """Checks ``key_material`` and returns copies of ``(aes_key, hmac_key)``."""
    if not isinstance(key_material, bytearray):
        raise TypeError('Parameter key_material is not bytearray instance.')
    if len(key_material) != KEY_MATERIAL_SIZE:
        raise ValueError('Parameter key_material must be 64 bytes long.')
    return key_material[:AES_KEY_SIZE], key_material[AES_KEY_SIZE:]


def encrypt_then_mac(
    cleardata: bytearray,
    key_material: bytearray,
    iv: bytearray,
    header: bytearray,
    *,
    authdata: Optional[bytearray] = None,
) -> Tuple[bytearray, bytearray]:
    r"""
    Encrypts the clear data, then authenticates the header and the cipherdata.

    .. code-block:: text

        aes_key, hmac_key = key_material[:32], key_material[32:]
        cipherdata        = AES-256-CBC(aes_key, iv, cleardata)
        hmac              = HMAC-SHA256(hmac_key, header, cipherdata, authdata)

    Parameters
    ----------
    cleardata : bytearray
        The message to encrypt. It is not modified (wiping it is up to the caller).

    key_material : bytearray
        64 bytes: ``aes_key (32) | hmac_key (32)``. It is not modified; the sub-key
        copies made by this function are wiped before returning.

    iv : bytearray
        The fresh 16-byte IV. It must also be contained in ``header``.

    header : bytearray
        The complete format-specific header (magic, version, ..., iv), authenticated
        by the HMAC.

    authdata : Optional[bytearray]
        Optional additional authenticated data (neither encrypted nor stored).

    Returns
    -------
    expected_hmac, cipherdata : tuple of bytearray
        The 32-byte HMAC tag and the encrypted data, ready for
        :func:`._common.bundle.join_bundle`.

    Raises
    ------
    TypeError
        If an argument is of the wrong type.
    ValueError
        If ``key_material`` is not 64 bytes long or ``iv`` is not 16 bytes long.
    """
    aes_key, hmac_key = _split_key_material(key_material)
    try:
        cipherdata = encrypt_AES_CBC(cleardata, aes_key, iv)
        expected_hmac = create_hmac(hmac_key, header, cipherdata, authdata)
        return expected_hmac, cipherdata
    finally:
        delete_bytearray(aes_key)
        delete_bytearray(hmac_key)


def verify_then_decrypt(
    header: bytearray,
    expected_hmac: bytearray,
    cipherdata: bytearray,
    key_material: bytearray,
    iv: bytearray,
    *,
    authdata: Optional[bytearray] = None,
    error_message: str = _DEFAULT_AUTH_ERROR_MESSAGE,
) -> bytearray:
    r"""
    Verifies the HMAC in constant time and, only if it is valid, decrypts the data.

    .. code-block:: text

        aes_key, hmac_key = key_material[:32], key_material[32:]
        check  HMAC-SHA256(hmac_key, header, cipherdata, authdata) == expected_hmac
        cleardata         = AES-256-CBC-decrypt(aes_key, iv, cipherdata)

    The cipherdata is never decrypted before the HMAC has been verified, which rules
    out padding-oracle attacks.

    Parameters
    ----------
    header : bytearray
        The exact header bytes read from the bundle (see :func:`._common.bundle.split_bundle`).

    expected_hmac : bytearray
        The 32-byte HMAC tag read from the bundle.

    cipherdata : bytearray
        The encrypted data read from the bundle.

    key_material : bytearray
        64 bytes: ``aes_key (32) | hmac_key (32)``. It is not modified; the sub-key
        copies made by this function are wiped before returning.

    iv : bytearray
        The 16-byte IV parsed from ``header``.

    authdata : Optional[bytearray]
        The additional authenticated data given at encryption (``None`` if none).

    error_message : str
        The message of the :class:`AuthError` raised when the HMAC does not match, so
        that each format can describe its own secret ("password" or "key").

    Returns
    -------
    cleardata : bytearray
        The decrypted message.

    Raises
    ------
    TypeError
        If an argument is of the wrong type.
    ValueError
        If ``key_material``, ``expected_hmac`` or ``iv`` has a wrong length.
    AuthError
        If the HMAC does not match: wrong password or key, wrong authdata, or
        tampered data.
    """
    aes_key, hmac_key = _split_key_material(key_material)
    try:
        computed_hmac = create_hmac(hmac_key, header, cipherdata, authdata)
        if not check_hmac(computed_hmac, expected_hmac):
            raise AuthError(error_message)
        # Decrypt only authenticated data
        return decrypt_AES_CBC(cipherdata, aes_key, iv)
    finally:
        delete_bytearray(aes_key)
        delete_bytearray(hmac_key)
