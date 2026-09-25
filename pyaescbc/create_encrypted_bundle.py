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

from .derive_key import MIN_ITERATIONS, MAX_ITERATIONS
from .__version__ import __version__

# ---------------------------------------------------------------------------
# Encrypted bundle format, version 2 (all integers are big-endian)
#
#   offset  size  field
#   0       4     magic       b"PACB"
#   4       1     version     int
#   5       4     iterations  uint32
#   9       32    salt
#   41      16    iv
#   ------------------------- header (57 bytes, authenticated by the HMAC)
#   57      32    hmac
#   89      16*n  cipherdata  (n >= 1)
# ---------------------------------------------------------------------------
MAGIC = b"PACB"
VERSION = int(__version__[0])
SALT_SIZE = 32
IV_SIZE = 16
HMAC_SIZE = 32
BLOCK_SIZE = 16

_PREFIX = struct.Struct(">4sBI")      
HEADER_SIZE = _PREFIX.size + SALT_SIZE + IV_SIZE     # 57
MIN_BUNDLE_SIZE = HEADER_SIZE + HMAC_SIZE + BLOCK_SIZE  # 105


def create_bundle_header(iterations: int, salt: bytearray, iv: bytearray) -> bytearray:
    r"""
    Creates the public header of an encrypted bundle (format version 2).

    The header contains every public parameter needed to decrypt the data and must be
    authenticated by the HMAC (see :func:`pyaescbc.create_hmac`).

    .. code-block:: text

        header = magic (4) | version (1) | iterations (4) | salt (32) | iv (16)

    Parameters
    ----------
    iterations : int
        The number of PBKDF2 iterations used to derive the key.

    salt : bytearray
        The 32-byte salt used to derive the key.

    iv : bytearray
        The 16-byte initialization vector used for encryption.

    Returns
    -------
    header : bytearray
        The 57-byte header.

    Raises
    ------
    TypeError
        If an argument is not of the correct type.
    ValueError
        If ``iterations`` is out of range or ``salt`` / ``iv`` have the wrong length.
    """
    # Check the types of the parameters
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise TypeError('Parameter iterations is not int instance.')
    if not isinstance(salt, bytearray):
        raise TypeError('Parameter salt is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')

    # Check the values of the parameters
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError(f'Parameter iterations must be between {MIN_ITERATIONS} and {MAX_ITERATIONS}.')
    if len(salt) != SALT_SIZE:
        raise ValueError('Parameter salt must be 32 bytes long.')
    if len(iv) != IV_SIZE:
        raise ValueError('Parameter iv must be 16 bytes long.')

    return bytearray().join((_PREFIX.pack(MAGIC, VERSION, iterations), salt, iv))


def create_encrypted_bundle(header: bytearray, expected_hmac: bytearray, cipherdata: bytearray) -> bytearray:
    r"""
    Creates the encrypted bundle containing all the information needed to decrypt the data.

    .. code-block:: text

        encrypted_bundle = header (57) | hmac (32) | cipherdata (16*n)

    .. seealso::

        - function :func:`pyaescbc.create_bundle_header` to create the header.
        - function :func:`pyaescbc.extract_cryptography_components` to parse the bundle.

    Parameters
    ----------
    header : bytearray
        The 57-byte header created by :func:`pyaescbc.create_bundle_header`.

    expected_hmac : bytearray
        The 32-byte HMAC computed over the header, the cipherdata and the authdata.

    cipherdata : bytearray
        The encrypted message (length is a positive multiple of 16).

    Returns
    -------
    encrypted_bundle : bytearray
        The encrypted bundle.

    Raises
    ------
    TypeError
        If any argument is not a ``bytearray`` instance.
    ValueError
        If any component has an invalid length or the header is not a version 2 header.
    """
    # Check the types of the parameters
    if not isinstance(header, bytearray):
        raise TypeError('Parameter header is not bytearray instance.')
    if not isinstance(expected_hmac, bytearray):
        raise TypeError('Parameter expected_hmac is not bytearray instance.')
    if not isinstance(cipherdata, bytearray):
        raise TypeError('Parameter cipherdata is not bytearray instance.')

    # Check the values of the parameters
    if len(header) != HEADER_SIZE or header[:4] != MAGIC or header[4] != VERSION:
        raise ValueError('Parameter header is not a valid version 2 header.')
    if len(expected_hmac) != HMAC_SIZE:
        raise ValueError('Parameter expected_hmac must be 32 bytes long.')
    if len(cipherdata) == 0 or len(cipherdata) % BLOCK_SIZE != 0:
        raise ValueError('Parameter cipherdata length must be a positive multiple of 16.')

    # Single allocation for the whole bundle
    return bytearray().join((header, expected_hmac, cipherdata))
