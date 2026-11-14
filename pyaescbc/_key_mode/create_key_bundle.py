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

import struct

from .._common.formats import PACK_MAGIC, IV_SIZE, HMAC_SIZE, BLOCK_SIZE
from .._common.bundle import join_bundle

# ---------------------------------------------------------------------------
# Key-mode encrypted bundle format, version 1 (all integers are big-endian)
#
#   offset  size  field
#   0       4     magic       b"PACK"
#   4       1     version     1
#   5       16    iv
#   ------------------------- header (21 bytes, authenticated by the HMAC)
#   21      32    hmac
#   53      16*n  cipherdata  (n >= 1)
#
# No salt and no iteration count: the key is random, there is nothing to stretch.
# ---------------------------------------------------------------------------
KEY_MAGIC = PACK_MAGIC
KEY_VERSION = 1           # format version: never derive it from the package version

_KEY_PREFIX = struct.Struct(">4sB")
KEY_HEADER_SIZE = _KEY_PREFIX.size + IV_SIZE                     # 21
KEY_MIN_BUNDLE_SIZE = KEY_HEADER_SIZE + HMAC_SIZE + BLOCK_SIZE   # 69


def create_key_bundle_header(iv: bytearray) -> bytearray:
    r"""
    Creates the public header of a key-mode encrypted bundle (key format version 1).

    The header must be authenticated by the HMAC (``create_hmac`` in ``_common.mac``).

    .. code-block:: text

        header = magic "PACK" (4) | version (1) | iv (16)

    Parameters
    ----------
    iv : bytearray
        The 16-byte initialization vector used for encryption.

    Returns
    -------
    header : bytearray
        The 21-byte header.

    Raises
    ------
    TypeError
        If ``iv`` is not a ``bytearray`` instance.
    ValueError
        If ``iv`` is not 16 bytes long.
    """
    # Check the types of the parameters
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')

    # Check the values of the parameters
    if len(iv) != IV_SIZE:
        raise ValueError('Parameter iv must be 16 bytes long.')

    return bytearray().join((_KEY_PREFIX.pack(KEY_MAGIC, KEY_VERSION), iv))


def create_key_encrypted_bundle(header: bytearray, expected_hmac: bytearray, cipherdata: bytearray) -> bytearray:
    r"""
    Creates the key-mode encrypted bundle.

    .. code-block:: text

        encrypted_bundle = header (21) | hmac (32) | cipherdata (16*n)

    .. seealso::

        - function :func:`create_key_bundle_header` to create the header.
        - function ``extract_key_bundle_components`` to parse the bundle.

    Parameters
    ----------
    header : bytearray
        The 21-byte header created by :func:`create_key_bundle_header`.

    expected_hmac : bytearray
        The 32-byte HMAC computed over the header, the cipherdata and the authdata.

    cipherdata : bytearray
        The encrypted message (length is a positive multiple of 16).

    Returns
    -------
    encrypted_bundle : bytearray
        The key-mode encrypted bundle.

    Raises
    ------
    TypeError
        If any argument is not a ``bytearray`` instance.
    ValueError
        If any component has an invalid length or the header is not a key-mode
        version 1 header.
    """
    # Check the types of the parameters
    if not isinstance(header, bytearray):
        raise TypeError('Parameter header is not bytearray instance.')
    if not isinstance(expected_hmac, bytearray):
        raise TypeError('Parameter expected_hmac is not bytearray instance.')
    if not isinstance(cipherdata, bytearray):
        raise TypeError('Parameter cipherdata is not bytearray instance.')

    # Check the format-specific header (the generic sizes are checked by join_bundle)
    if len(header) != KEY_HEADER_SIZE or header[:4] != KEY_MAGIC or header[4] != KEY_VERSION:
        raise ValueError('Parameter header is not a valid key-mode version 1 header.')

    # Generic layout: header | hmac (32) | cipherdata (16*n)
    return join_bundle(header, expected_hmac, cipherdata)
