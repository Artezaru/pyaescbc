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
from .create_encrypted_bundle import _PREFIX, MAGIC, VERSION, SALT_SIZE, IV_SIZE, HEADER_SIZE
from .derive_key import MIN_ITERATIONS, MAX_ITERATIONS


class BundleComponents(NamedTuple):
    """Components of a version 2 encrypted bundle (all byte fields are copies)."""
    header: bytearray         # the exact header bytes, to be passed to create_hmac
    iterations: int
    salt: bytearray
    iv: bytearray
    expected_hmac: bytearray
    cipherdata: bytearray


def extract_cryptography_components(encrypted_bundle: bytearray) -> BundleComponents:
    r"""
    Parses and validates a password-mode encrypted bundle (format version 2).

    The structure of the bundle is validated (magic, version, iteration bounds, lengths)
    BEFORE any key derivation, so that a malformed or malicious bundle is rejected cheaply.
    The data is NOT authenticated by this function: the HMAC must be checked afterwards.

    .. code-block:: text

        encrypted_bundle = magic (4) | version (1) | iterations (4) | salt (32) | iv (16)
                         | hmac (32) | cipherdata (16*n)

    .. seealso::

        - function ``create_encrypted_bundle`` to create the encrypted bundle.

    Parameters
    ----------
    encrypted_bundle : bytearray
        The encrypted bundle. It is not modified.

    Returns
    -------
    BundleComponents
        Named tuple ``(header, iterations, salt, iv, expected_hmac, cipherdata)``.
        ``header`` is the exact byte sequence to authenticate with ``create_hmac``
        (in ``_common.mac``).

    Raises
    ------
    TypeError
        If the argument is not a ``bytearray`` instance.
    ValueError
        If the bundle is malformed, has an unknown magic or version, its iteration
        count is out of the allowed range, or it is a key-mode bundle (use
        ``pyaescbc.decrypt_with_key`` for those).
    """
    # Bundle of the other mode: clear message, before the size checks (which use the
    # header size of this mode and would otherwise reject it first)
    if bundle_kind(encrypted_bundle) == "key":
        raise ValueError('Invalid encrypted bundle: this is a key-mode bundle, use decrypt_with_key().')

    # Generic structure: type, minimum size, 16-byte alignment (see split_bundle)
    parts = split_bundle(encrypted_bundle, HEADER_SIZE)

    # Format-specific header
    magic, version, iterations = _PREFIX.unpack_from(parts.header, 0)
    if magic != MAGIC:
        raise ValueError('Invalid encrypted bundle: unknown format (legacy v1 bundle?).')
    if version != VERSION:
        raise ValueError(f'Invalid encrypted bundle: unsupported version {version}.')
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError('Invalid encrypted bundle: iterations out of the allowed range.')

    # Extract the header fields (slices of a bytearray are independent bytearray copies)
    offset = _PREFIX.size
    salt = parts.header[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    iv = parts.header[offset:offset + IV_SIZE]

    return BundleComponents(parts.header, iterations, salt, iv, parts.expected_hmac, parts.cipherdata)