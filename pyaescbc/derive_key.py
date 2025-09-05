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

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: bytearray, salt: bytearray, iterations: int) -> bytearray:
    """
    Derives a 64-byte key from a password using PBKDF2HMAC.
    The algorithm used is SHA256.

    The derived key is composed by the AES key and the HMAC key, both 32 bytes long.
    The AES key is used to encrypt or decrypt the data using AES in CBC mode.
    The HMAC key is used to create the HMAC to verify the integrity of the data.

    By default, the input parameters are deleted from memory at the end of the function.

    .. seealso::

        -function :func:`pyaescbc.encrypt_AES_CBC` to encrypt the data using AES in CBC mode.
        -function :func:`pyaescbc.decrypt_AES_CBC` to decrypt the data using AES in CBC mode.
        -function :func:`pyaescbc.create_hmac` to create the HMAC of the data.

    Parameters
    ----------
    password : bytearray
        The user password. It must not be empty.

    salt : bytearray
        The 32-byte salt used to generate the derived key.

    iterations : int
        The number of iterations for PBKDF2. It must be a strictly positive integer.

    Returns
    -------
    derived_key : bytearray
        The derived 64-byte key.

    Raises
    ------
    TypeError
        If the arguments are not of the correct types.
    ValueError
        If `iterations` is not a strictly positive integer, `salt` is not 32 bytes long, or `password` is empty.
    """
    # Check the types of the parameters
    if not isinstance(password, bytearray):
        raise TypeError('Parameter password is not bytearray instance.')
    if not isinstance(salt, bytearray):
        raise TypeError('Parameter salt is not bytearray instance.')
    if not isinstance(iterations, int):
        raise TypeError('Parameter iterations is not int instance.')

    # Check the values of the parameters
    if len(password) == 0:
        raise ValueError('Parameter password must not be empty.')
    if iterations <= 0:
        raise ValueError('Parameter iterations must be a positive integer.')
    if len(salt) != 32:
        raise ValueError(f'{salt=} is not 32 bytes long.') 

    # Derive the key using PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=64,  # 32 bytes for AES + 32 bytes for HMAC
                     salt=bytes(salt),
                     iterations=iterations,
                     backend=default_backend())
    derived_key = bytearray(kdf.derive(password))
    return derived_key