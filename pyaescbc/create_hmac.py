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

import hashlib
import hmac
import struct
from typing import Optional


def create_hmac(hmac_key: bytearray, header: bytearray, cipherdata: bytearray, authdata: Optional[bytearray] = None) -> bytearray:
    r"""
    Creates the HMAC-SHA256 tag authenticating the header, the cipherdata and the optional authdata.

    Each field is prefixed with its length encoded as an 8-byte big-endian unsigned integer.
    This makes the encoding unambiguous: bytes cannot be moved from one field to another
    (for example from the end of ``cipherdata`` to the beginning of ``authdata``) without
    changing the tag.

    .. code-block:: text

        tag = HMAC-SHA256(hmac_key, len(header) || header || len(cipherdata) || cipherdata || len(authdata) || authdata)

    The ``header`` must contain every public parameter needed to decrypt the bundle
    (version, iterations, salt, iv, ...) so that none of them can be tampered with.

    .. note::

        ``authdata=None`` and an empty ``authdata`` produce the same tag.

    .. seealso::

        - function :func:`pyaescbc.derive_key` to create the HMAC key.
        - function :func:`pyaescbc.check_hmac` to compare two tags in constant time.

    Parameters
    ----------
    hmac_key : bytearray
        The 32-byte key used to create the HMAC (``derived_key[32:]``).

    header : bytearray
        The public header of the encrypted bundle (everything before the cipherdata).

    cipherdata : bytearray
        The encrypted message.

    authdata : Optional[bytearray]
        Optional additional authenticated data (not encrypted, not stored in the bundle).

    Returns
    -------
    expected_hmac : bytearray
        The 32-byte HMAC tag.

    Raises
    ------
    TypeError
        If any argument is not a ``bytearray`` instance.
    ValueError
        If ``hmac_key`` isn't 32 bytes long.
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
    if len(hmac_key) != 32:
        raise ValueError('Parameter hmac_key must be 32 bytes long.')

    if authdata is None:
        authdata = bytearray()

    # Create the HMAC incrementally (no concatenated copy of the inputs)
    mac = hmac.new(hmac_key, digestmod=hashlib.sha256)
    for field in (header, cipherdata, authdata):
        mac.update(struct.pack('>Q', len(field)))
        mac.update(field)
    return bytearray(mac.digest())