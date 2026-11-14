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
Fast key expansion shared by every format.

Only the HKDF step lives here. The slow, password-specific step (PBKDF2) belongs to
the password mode (``_password_mode/derive_key.py``): a random key has nothing to stretch.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .formats import AES_KEY_SIZE, HMAC_KEY_SIZE, KEY_MATERIAL_SIZE

#: Size of the secret accepted by :func:`hkdf_expand_pair`.
SECRET_SIZE = 32


def hkdf_expand_pair(secret, info_aes: bytes, info_hmac: bytes) -> bytearray:
    r"""
    Expands a 32-byte uniformly random secret into an AES key and an HMAC key.

    .. code-block:: text

        aes_key  = HKDF-Expand-SHA256(secret, info_aes,  32)
        hmac_key = HKDF-Expand-SHA256(secret, info_hmac, 32)
        key_material = aes_key || hmac_key

    The two labels give two independent keys (key separation). Each format passes its
    own labels, so that the same secret never yields the same keys in two formats.

    .. warning::

        There is no salt and no iteration: ``secret`` must already be uniformly random
        (the output of PBKDF2, or a key from ``generate_key``). Never pass a password.

    Parameters
    ----------
    secret : bytes or bytearray
        The 32-byte secret (``bytes`` is accepted because PBKDF2 returns ``bytes``).
        It is not modified.

    info_aes : bytes
        The context label of the AES key.

    info_hmac : bytes
        The context label of the HMAC key. Must differ from ``info_aes``.

    Returns
    -------
    key_material : bytearray
        64 bytes: ``aes_key (32) | hmac_key (32)``. The caller must wipe it after use.

    Raises
    ------
    TypeError
        If ``secret`` is not ``bytes``/``bytearray`` or a label is not ``bytes``.
    ValueError
        If ``secret`` is not 32 bytes long, a label is empty, or both labels are equal.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError('Parameter secret is not bytes or bytearray instance.')
    if not isinstance(info_aes, bytes) or not isinstance(info_hmac, bytes):
        raise TypeError('Parameters info_aes and info_hmac must be bytes instances.')

    if len(secret) != SECRET_SIZE:
        raise ValueError('Parameter secret must be 32 bytes long.')
    if not info_aes or not info_hmac:
        raise ValueError('Parameters info_aes and info_hmac must not be empty.')
    if info_aes == info_hmac:
        raise ValueError('Parameters info_aes and info_hmac must differ.')

    key_material = bytearray(KEY_MATERIAL_SIZE)
    key_material[:AES_KEY_SIZE] = HKDFExpand(
        algorithm=hashes.SHA256(), length=AES_KEY_SIZE, info=info_aes,
    ).derive(secret)
    key_material[AES_KEY_SIZE:] = HKDFExpand(
        algorithm=hashes.SHA256(), length=HMAC_KEY_SIZE, info=info_hmac,
    ).derive(secret)
    return key_material
