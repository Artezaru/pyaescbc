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
HMAC-SHA256 tag of a bundle, and constant-time tag comparison.
"""

import hashlib
import hmac
import struct
from typing import Optional

from .formats import HMAC_SIZE, HMAC_KEY_SIZE


def create_hmac(hmac_key: bytearray, header: bytearray, cipherdata: bytearray, authdata: Optional[bytearray] = None) -> bytearray:
    r"""
    Creates the HMAC-SHA256 tag authenticating the header, the cipherdata and the optional authdata.

    Each field is prefixed with its length encoded as an 8-byte big-endian unsigned integer.
    This makes the encoding unambiguous: bytes cannot be moved from one field to another
    (for example from the end of ``cipherdata`` to the beginning of ``authdata``) without
    changing the tag.

    .. code-block:: text

        tag = HMAC-SHA256(hmac_key, len(header)     || header
                                 || len(cipherdata) || cipherdata
                                 || len(authdata)   || authdata)

    The ``header`` must contain every public parameter needed to decrypt the bundle
    (magic, version, salt, iterations, iv, ... depending on the format), so that none of
    them can be tampered with.

    .. note::

        ``authdata=None`` and an empty ``authdata`` produce the same tag.

    Parameters
    ----------
    hmac_key : bytearray
        The 32-byte HMAC key (``key_material[32:]``). It is not modified.

    header : bytearray
        The complete public header of the bundle. It is not modified.

    cipherdata : bytearray
        The encrypted data. It is not modified.

    authdata : Optional[bytearray]
        Optional additional authenticated data (neither encrypted nor stored in the
        bundle). It is not modified.

    Returns
    -------
    tag : bytearray
        The 32-byte HMAC tag.

    Raises
    ------
    TypeError
        If an argument is not a ``bytearray`` instance (``authdata`` may also be ``None``).
    ValueError
        If ``hmac_key`` is not 32 bytes long.
    """
    # Check the types of the parameters
    if not isinstance(hmac_key, bytearray):
        raise TypeError('Parameter hmac_key is not bytearray instance.')
    if not isinstance(header, bytearray):
        raise TypeError('Parameter header is not bytearray instance.')
    if not isinstance(cipherdata, bytearray):
        raise TypeError('Parameter cipherdata is not bytearray instance.')
    if authdata is not None and not isinstance(authdata, bytearray):
        raise TypeError('Parameter authdata is not bytearray instance.')

    # Check the values of the parameters (never include the values in the messages)
    if len(hmac_key) != HMAC_KEY_SIZE:
        raise ValueError('Parameter hmac_key must be 32 bytes long.')

    if authdata is None:
        authdata = bytearray()

    # Create the HMAC incrementally (no concatenated copy of the inputs)
    mac = hmac.new(hmac_key, digestmod=hashlib.sha256)
    for field in (header, cipherdata, authdata):
        mac.update(struct.pack('>Q', len(field)))
        mac.update(field)
    return bytearray(mac.digest())


def check_hmac(given_hmac: bytearray, expected_hmac: bytearray) -> bool:
    r"""
    Compares two HMAC tags in constant time.

    The comparison time does not depend on how many leading bytes match, so it leaks
    nothing about the expected tag (see :func:`hmac.compare_digest`).

    Parameters
    ----------
    given_hmac : bytearray
        The 32-byte tag computed from the data (see :func:`create_hmac`).

    expected_hmac : bytearray
        The 32-byte tag stored in the bundle.

    Returns
    -------
    bool
        ``True`` if the tags are equal, ``False`` otherwise.

    Raises
    ------
    TypeError
        If an argument is not a ``bytearray`` instance.
    ValueError
        If a tag is not 32 bytes long.
    """
    # Check the types of the parameters
    if not isinstance(given_hmac, bytearray):
        raise TypeError('Parameter given_hmac is not bytearray instance.')
    if not isinstance(expected_hmac, bytearray):
        raise TypeError('Parameter expected_hmac is not bytearray instance.')

    # Check the values of the parameters (never include the values in the messages)
    if len(given_hmac) != HMAC_SIZE:
        raise ValueError('Parameter given_hmac must be 32 bytes long.')
    if len(expected_hmac) != HMAC_SIZE:
        raise ValueError('Parameter expected_hmac must be 32 bytes long.')

    return hmac.compare_digest(given_hmac, expected_hmac)
