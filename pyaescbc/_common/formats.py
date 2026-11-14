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
Constants shared by every bundle format, and bundle identification.

Every format uses the same layout (see :mod:`._common.bundle`)::

    header (format-specific, starts with a 4-byte magic) | hmac (32) | cipherdata (16*n)

Only the magic and the rest of the header differ between formats.
"""

from typing import Literal, Optional

#: Magic of a password-mode bundle (``pyaescbc.encrypt``).
PACB_MAGIC = b"PACB"

#: Magic of a key-mode bundle (``pyaescbc.encrypt_with_key``).
PACK_MAGIC = b"PACK"

#: Size of every magic, in bytes.
MAGIC_SIZE = 4

#: AES block size, IV size, HMAC-SHA256 tag size, salt size, in bytes.
BLOCK_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 32
SALT_SIZE = 32

#: Size of a key material: ``aes_key (32) | hmac_key (32)``.
AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32
KEY_MATERIAL_SIZE = AES_KEY_SIZE + HMAC_KEY_SIZE

BundleKind = Literal["password", "key"]

_KINDS = {PACB_MAGIC: "password", PACK_MAGIC: "key"}


def bundle_kind(encrypted_bundle: bytearray) -> Optional[BundleKind]:
    r"""
    Identifies the format of a bundle from its magic only.

    The bundle is neither validated nor authenticated: this is only used to give a
    clear error message when a bundle is passed to the wrong function.

    Parameters
    ----------
    encrypted_bundle : bytearray
        Any bytes. It is not modified.

    Returns
    -------
    kind : {"password", "key"} or None
        ``"password"`` for a ``PACB`` bundle, ``"key"`` for a ``PACK`` bundle,
        ``None`` if the magic is unknown (or the data is shorter than a magic).

    Raises
    ------
    TypeError
        If ``encrypted_bundle`` is not a ``bytearray`` instance.
    """
    if not isinstance(encrypted_bundle, bytearray):
        raise TypeError('Parameter encrypted_bundle is not bytearray instance.')
    return _KINDS.get(bytes(encrypted_bundle[:MAGIC_SIZE]))
