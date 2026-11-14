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
Key generation and key expansion of the key mode (``PACK`` bundles).
"""

from .._common.kdf import hkdf_expand_pair
from .._common.random import random_bytearray

#: Size in bytes of a key-mode key.
KEY_SIZE = 32

# HKDF context labels of the key mode. They differ from the password-mode labels, so the
# same 32 bytes never yield the same sub-keys in both modes.
# NEVER change them: existing bundles could no longer be decrypted.
_INFO_AES = b"pyaescbc key-mode v1 aes-256-cbc key"
_INFO_HMAC = b"pyaescbc key-mode v1 hmac-sha256 key"


def generate_key() -> bytearray:
    r"""
    Generates a random key for the key mode (``pyaescbc.encrypt_with_key``).

    .. code-block:: python

        import pyaescbc

        key = pyaescbc.generate_key()  # 32 random bytes

    The key must be kept secret. To store it, encrypt it with a password using
    ``pyaescbc.encrypt`` ("key wrapping"): the slow key derivation then runs once,
    when the key is unwrapped, instead of once per message.

    Returns
    -------
    key : bytearray
        :data:`KEY_SIZE` (32) bytes from the operating system CSPRNG.
        Wipe it with ``pyaescbc.delete_bytearray`` when it is no longer needed.
    """
    return random_bytearray(KEY_SIZE)


def expand_key(key: bytearray) -> bytearray:
    r"""
    Expands a key-mode key into the 64-byte key material (AES key + HMAC key).

    .. code-block:: text

        key_material = hkdf_expand_pair(key,
                                        "pyaescbc key-mode v1 aes-256-cbc key",
                                        "pyaescbc key-mode v1 hmac-sha256 key")

    There is no salt and no iteration: the key must be uniformly random (see
    :func:`generate_key`). Internal building block: never pass a password here, use
    the password mode for passwords.

    Parameters
    ----------
    key : bytearray
        The 32-byte key. It is not modified.

    Returns
    -------
    key_material : bytearray
        64 bytes: ``aes_key (32) | hmac_key (32)``. The caller must wipe it after use.

    Raises
    ------
    TypeError
        If ``key`` is not a ``bytearray`` instance.
    ValueError
        If ``key`` is not 32 bytes long.
    """
    if not isinstance(key, bytearray):
        raise TypeError('Parameter key is not bytearray instance.')
    if len(key) != KEY_SIZE:
        raise ValueError(f'Parameter key must be {KEY_SIZE} bytes long.')

    return hkdf_expand_pair(key, _INFO_AES, _INFO_HMAC)
