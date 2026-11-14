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
Generic layout of an encrypted bundle, shared by every format::

    header (header_size) | hmac (32) | cipherdata (16*n, n >= 1)

The content of the header (magic, version, salt, iv, ...) is format-specific and is
parsed by each format; this module only checks the sizes and cuts the bundle.
"""

from typing import NamedTuple

from .formats import HMAC_SIZE, BLOCK_SIZE


class BundleParts(NamedTuple):
    """The three parts of an encrypted bundle (independent ``bytearray`` copies)."""
    header: bytearray         # exact header bytes, to be authenticated by the HMAC
    expected_hmac: bytearray  # the 32-byte tag stored in the bundle
    cipherdata: bytearray     # the encrypted data, a positive multiple of 16 bytes


def join_bundle(header: bytearray, expected_hmac: bytearray, cipherdata: bytearray) -> bytearray:
    r"""
    Assembles an encrypted bundle.

    .. code-block:: text

        encrypted_bundle = header | hmac (32) | cipherdata (16*n)

    The header itself is built and validated by the format (magic, version, ...).

    Parameters
    ----------
    header : bytearray
        The non-empty, format-specific header.

    expected_hmac : bytearray
        The 32-byte HMAC tag over the header, the cipherdata and the authdata.

    cipherdata : bytearray
        The encrypted data (length is a positive multiple of 16).

    Returns
    -------
    encrypted_bundle : bytearray
        A new bytearray; the arguments are not modified.

    Raises
    ------
    TypeError
        If any argument is not a ``bytearray`` instance.
    ValueError
        If ``header`` is empty, ``expected_hmac`` is not 32 bytes long, or the length of
        ``cipherdata`` is not a positive multiple of 16.
    """
    if not isinstance(header, bytearray):
        raise TypeError('Parameter header is not bytearray instance.')
    if not isinstance(expected_hmac, bytearray):
        raise TypeError('Parameter expected_hmac is not bytearray instance.')
    if not isinstance(cipherdata, bytearray):
        raise TypeError('Parameter cipherdata is not bytearray instance.')

    if len(header) == 0:
        raise ValueError('Parameter header must not be empty.')
    if len(expected_hmac) != HMAC_SIZE:
        raise ValueError('Parameter expected_hmac must be 32 bytes long.')
    if len(cipherdata) == 0 or len(cipherdata) % BLOCK_SIZE != 0:
        raise ValueError('Parameter cipherdata length must be a positive multiple of 16.')

    # Single allocation for the whole bundle
    return bytearray().join((header, expected_hmac, cipherdata))


def split_bundle(encrypted_bundle: bytearray, header_size: int) -> BundleParts:
    r"""
    Checks the sizes of an encrypted bundle and cuts it into its three parts.

    Only the lengths are checked: the header content must then be parsed by the
    format, and the HMAC verified (see :func:`._common.etm.verify_then_decrypt`).

    Parameters
    ----------
    encrypted_bundle : bytearray
        The encrypted bundle. It is not modified.

    header_size : int
        The size of the format-specific header (strictly positive).

    Returns
    -------
    BundleParts
        Named tuple ``(header, expected_hmac, cipherdata)`` of independent copies.

    Raises
    ------
    TypeError
        If ``encrypted_bundle`` is not a ``bytearray`` or ``header_size`` not an ``int``.
    ValueError
        If ``header_size`` is not strictly positive, the bundle is too short, or the
        length of its cipherdata is not a multiple of 16.
    """
    if not isinstance(encrypted_bundle, bytearray):
        raise TypeError('Parameter encrypted_bundle is not bytearray instance.')
    if not isinstance(header_size, int) or isinstance(header_size, bool):
        raise TypeError('Parameter header_size is not int instance.')
    if header_size <= 0:
        raise ValueError('Parameter header_size must be strictly positive.')

    if len(encrypted_bundle) < header_size + HMAC_SIZE + BLOCK_SIZE:
        raise ValueError('Invalid encrypted bundle: too short.')
    if (len(encrypted_bundle) - header_size - HMAC_SIZE) % BLOCK_SIZE != 0:
        raise ValueError('Invalid encrypted bundle: cipherdata length is not a multiple of 16.')

    # Slices of a bytearray are independent bytearray copies
    return BundleParts(
        header=encrypted_bundle[:header_size],
        expected_hmac=encrypted_bundle[header_size:header_size + HMAC_SIZE],
        cipherdata=encrypted_bundle[header_size + HMAC_SIZE:],
    )
