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
Random data from the operating system CSPRNG (``os.urandom``).
"""

import os

from .formats import IV_SIZE, SALT_SIZE


def random_bytearray(n_bytes: int) -> bytearray:
    r"""
    Generates ``n_bytes`` cryptographically secure random bytes.

    Parameters
    ----------
    n_bytes : int
        The number of bytes (zero or more).

    Returns
    -------
    barray : bytearray
        ``n_bytes`` bytes from :func:`os.urandom`.

    Raises
    ------
    TypeError
        If ``n_bytes`` is not an ``int`` (``bool`` is rejected).
    ValueError
        If ``n_bytes`` is negative.
    """
    # bool is a subclass of int and must be rejected
    if not isinstance(n_bytes, int) or isinstance(n_bytes, bool):
        raise TypeError('Parameter n_bytes is not int instance.')
    if n_bytes < 0:
        raise ValueError('Parameter n_bytes must not be negative.')

    return bytearray(os.urandom(n_bytes))


def random_iv() -> bytearray:
    r"""
    Generates a fresh 16-byte initialization vector for AES-CBC.

    A new IV must be generated for every encryption and never reused with the same key.

    Returns
    -------
    iv : bytearray
        16 random bytes.
    """
    return random_bytearray(IV_SIZE)


def random_salt() -> bytearray:
    r"""
    Generates a fresh 32-byte salt for the password key derivation.

    Returns
    -------
    salt : bytearray
        32 random bytes.
    """
    return random_bytearray(SALT_SIZE)
