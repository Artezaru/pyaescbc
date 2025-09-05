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

from cryptography.hazmat.primitives import padding, ciphers
from cryptography.hazmat.backends import default_backend

def encrypt_AES_CBC(cleardata: bytearray, aes_key: bytearray, iv: bytearray) -> bytearray:
    r"""
    Encrypts a cleardata message using AES in CBC mode.

    The cleardata is padded using PKCS7 padding and then encrypted using AES in CBC mode.
    The aes_key is the first 32 bytes of the derived key, and the iv is the initialization vector.

    .. seealso::

        function :func:`pyaescbc.derive_key` to create the derived key.

    .. note::

        The cleardata, aes_key and iv must be bytearrays.

    Parameters
    ----------
    cleardata : bytearray
        The message to encrypt using AES in CBC mode.

    aes_key : bytearray
        The 32-byte AES key derived from the password, salt and iterations.

    iv : bytearray
        The 16-byte initialization vector (IV) to use in AES-CBC mode.

    Returns
    -------
    cipherdata: bytearray
        The encrypted message.

    Raises
    ------
    TypeError
        If a given argument is not a `bytearray` instance.
    ValueError
        If the `aes_key` isn't 32 bytes long or the `iv` isn't 16 bytes long.
    """
    # Check the types of the parameters
    if not isinstance(cleardata, bytearray):
        raise TypeError('Parameter cleardata is not bytearray instance.')
    if not isinstance(aes_key, bytearray):
        raise TypeError('Parameter aes_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')

    # Check the values of the parameters
    if len(aes_key) != 32:
        raise ValueError(f'{aes_key=} is not 32 bytes long.') 
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.')
    
    # Encrypt the data using AES in CBC mode
    padder = padding.PKCS7(128).padder()  
    cipher = ciphers.Cipher(ciphers.algorithms.AES(aes_key), ciphers.modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = padder.update(cleardata) + padder.finalize()
    cipherdata = bytearray(encryptor.update(padded_data) + encryptor.finalize())
    return cipherdata
