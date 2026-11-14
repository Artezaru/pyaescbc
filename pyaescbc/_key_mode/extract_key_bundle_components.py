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

from typing import NamedTuple

from .._common.formats import bundle_kind
from .._common.bundle import split_bundle
from .create_key_bundle import _KEY_PREFIX, KEY_MAGIC, KEY_VERSION, KEY_HEADER_SIZE


class KeyBundleComponents(NamedTuple):
    """Components of a key-mode encrypted bundle (all byte fields are copies)."""
    header: bytearray         # the exact header bytes, to be passed to create_hmac
    iv: bytearray
    expected_hmac: bytearray
    cipherdata: bytearray


def extract_key_bundle_components(encrypted_bundle: bytearray) -> KeyBundleComponents:
    r"""
    Parses and validates a key-mode encrypted bundle (key format version 1).

    The structure of the bundle is validated (magic, version, lengths) but the data is
    NOT authenticated by this function: the HMAC must be checked afterwards.

    .. code-block:: text

        encrypted_bundle = magic "PACK" (4) | version (1) | iv (16) | hmac (32) | cipherdata (16*n)

    .. seealso::

        - function ``create_key_encrypted_bundle`` to create the encrypted bundle.

    Parameters
    ----------
    encrypted_bundle : bytearray
        The key-mode encrypted bundle. It is not modified.

    Returns
    -------
    KeyBundleComponents
        Named tuple ``(header, iv, expected_hmac, cipherdata)``.
        ``header`` is the exact byte sequence to authenticate with ``create_hmac``
        (in ``_common.mac``).

    Raises
    ------
    TypeError
        If the argument is not a ``bytearray`` instance.
    ValueError
        If the bundle is malformed, has an unknown magic or version, or is a
        password-mode bundle (use ``pyaescbc.decrypt`` for those).
    """
    # Bundle of the other mode: clear message, before the size checks (which use the
    # header size of this mode and would otherwise reject it first)
    if bundle_kind(encrypted_bundle) == "password":
        raise ValueError('Invalid key-mode bundle: this is a password-mode bundle, use decrypt().')

    # Generic structure: type, minimum size, 16-byte alignment (see split_bundle)
    parts = split_bundle(encrypted_bundle, KEY_HEADER_SIZE)

    # Format-specific header
    magic, version = _KEY_PREFIX.unpack_from(parts.header, 0)
    if magic != KEY_MAGIC:
        raise ValueError('Invalid key-mode bundle: unknown format.')
    if version != KEY_VERSION:
        raise ValueError(f'Invalid key-mode bundle: unsupported version {version}.')

    # Extract the header fields (slices of a bytearray are independent bytearray copies)
    iv = parts.header[_KEY_PREFIX.size:KEY_HEADER_SIZE]

    return KeyBundleComponents(parts.header, iv, parts.expected_hmac, parts.cipherdata)
