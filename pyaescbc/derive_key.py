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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


#: Minimum number of PBKDF2 iterations accepted (prevents weak settings).
MIN_ITERATIONS = 100_000

#: Maximum number of PBKDF2 iterations accepted (prevents denial of service
#: when the iteration count is read from an untrusted bundle).
MAX_ITERATIONS = 100_000_000

# Context labels for HKDF: each label yields an independent key.
_INFO_AES = b"pyaescbc v2 aes-256-cbc key"
_INFO_HMAC = b"pyaescbc v2 hmac-sha256 key"


def derive_key(password: bytearray, salt: bytearray, iterations: int) -> bytearray:
    r"""
    Derives the 64-byte key material (AES key + HMAC key) from a password.

    The derivation is done in two steps:

    1. A 32-byte master key is derived from the password with PBKDF2-HMAC-SHA256
       (the slow, brute-force resistant step).
    2. Two independent 32-byte keys are expanded from the master key with HKDF-SHA256,
       using distinct context labels (the fast, key separation step).

    .. code-block:: text

        master_key = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
        aes_key    = HKDF-Expand-SHA256(master_key, "pyaescbc v2 aes-256-cbc key", 32)
        hmac_key   = HKDF-Expand-SHA256(master_key, "pyaescbc v2 hmac-sha256 key", 32)
        derived_key = aes_key || hmac_key

    Deriving a single 32-byte PBKDF2 output (instead of 64) ensures that an attacker
    has to perform exactly the same amount of work as the legitimate user for each
    password guess.

    .. seealso::

        - function :func:`pyaescbc.encrypt_AES_CBC` to encrypt the data using AES in CBC mode.
        - function :func:`pyaescbc.decrypt_AES_CBC` to decrypt the data using AES in CBC mode.
        - function :func:`pyaescbc.create_hmac` to create the HMAC of the data.

    .. note::

        This function does not modify or delete its inputs. Intermediate values produced
        by the ``cryptography`` library are immutable ``bytes`` and cannot be wiped.

    Parameters
    ----------
    password : bytearray
        The user password. It must not be empty.

    salt : bytearray
        The 32-byte random salt (see :func:`pyaescbc.random_salt`).

    iterations : int
        The number of PBKDF2 iterations, between ``MIN_ITERATIONS`` (100 000)
        and ``MAX_ITERATIONS`` (100 000 000).

    Returns
    -------
    derived_key : bytearray
        The derived 64-byte key: ``derived_key[:32]`` is the AES key and
        ``derived_key[32:]`` is the HMAC key.

    Raises
    ------
    TypeError
        If the arguments are not of the correct types.
    ValueError
        If ``password`` is empty, ``salt`` is not 32 bytes long, or ``iterations``
        is out of the allowed range.
    """
    # Check the types of the parameters (bool is a subclass of int and must be rejected)
    if not isinstance(password, bytearray):
        raise TypeError('Parameter password is not bytearray instance.')
    if not isinstance(salt, bytearray):
        raise TypeError('Parameter salt is not bytearray instance.')
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise TypeError('Parameter iterations is not int instance.')

    # Check the values of the parameters (never include the values in the messages)
    if len(password) == 0:
        raise ValueError('Parameter password must not be empty.')
    if len(salt) != 32:
        raise ValueError('Parameter salt must be 32 bytes long.')
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError(f'Parameter iterations must be between {MIN_ITERATIONS} and {MAX_ITERATIONS}.')

    # Step 1: slow derivation of a single 32-byte master key
    master_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),  # the salt is public, the library requires bytes
        iterations=iterations,
    ).derive(password)

    # Step 2: fast expansion into two independent keys
    derived_key = bytearray(64)
    derived_key[:32] = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=_INFO_AES).derive(master_key)
    derived_key[32:] = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=_INFO_HMAC).derive(master_key)
    return derived_key