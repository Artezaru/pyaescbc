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

from .create_encrypted_bundle import (
    _PREFIX, MAGIC, VERSION, SALT_SIZE, IV_SIZE, HMAC_SIZE, BLOCK_SIZE,
    HEADER_SIZE, MIN_BUNDLE_SIZE,
)
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
    Parses and validates a version 2 encrypted bundle.

    The structure of the bundle is validated (magic, version, iteration bounds, lengths)
    BEFORE any key derivation, so that a malformed or malicious bundle is rejected cheaply.
    The data is NOT authenticated by this function: the HMAC must be checked afterwards.

    .. code-block:: text

        encrypted_bundle = magic (4) | version (1) | iterations (4) | salt (32) | iv (16)
                         | hmac (32) | cipherdata (16*n)

    .. seealso::

        - function :func:`pyaescbc.create_encrypted_bundle` to create the encrypted bundle.

    Parameters
    ----------
    encrypted_bundle : bytearray
        The encrypted bundle. It is not modified.

    Returns
    -------
    BundleComponents
        Named tuple ``(header, iterations, salt, iv, expected_hmac, cipherdata)``.
        ``header`` is the exact byte sequence to authenticate with :func:`pyaescbc.create_hmac`.

    Raises
    ------
    TypeError
        If the argument is not a ``bytearray`` instance.
    ValueError
        If the bundle is malformed, has an unknown magic or version, or its iteration
        count is out of the allowed range.
    """
    # Check the types of the parameters
    if not isinstance(encrypted_bundle, bytearray):
        raise TypeError('Parameter encrypted_bundle is not bytearray instance.')

    # Check the structure of the bundle
    if len(encrypted_bundle) < MIN_BUNDLE_SIZE:
        raise ValueError('Invalid encrypted bundle: too short.')
    if (len(encrypted_bundle) - HEADER_SIZE - HMAC_SIZE) % BLOCK_SIZE != 0:
        raise ValueError('Invalid encrypted bundle: cipherdata length is not a multiple of 16.')

    magic, version, iterations = _PREFIX.unpack_from(encrypted_bundle, 0)
    if magic != MAGIC:
        raise ValueError('Invalid encrypted bundle: unknown format (legacy v1 bundle?).')
    if version != VERSION:
        raise ValueError(f'Invalid encrypted bundle: unsupported version {version}.')
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError('Invalid encrypted bundle: iterations out of the allowed range.')

    # Extract the components (slices of a bytearray are independent bytearray copies)
    offset = _PREFIX.size
    salt = encrypted_bundle[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    iv = encrypted_bundle[offset:offset + IV_SIZE]
    header = encrypted_bundle[:HEADER_SIZE]
    expected_hmac = encrypted_bundle[HEADER_SIZE:HEADER_SIZE + HMAC_SIZE]
    cipherdata = encrypted_bundle[HEADER_SIZE + HMAC_SIZE:]

    return BundleComponents(header, iterations, salt, iv, expected_hmac, cipherdata)