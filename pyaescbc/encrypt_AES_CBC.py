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
from .delete_bytearray import delete_bytearray

def encrypt_AES_CBC(cleardata: bytearray, aes_key: bytearray, iv: bytearray) -> bytearray:
    r"""
    Encrypts a cleardata message using AES-256 in CBC mode.

    The cleardata is padded using PKCS7 padding and then encrypted using AES-256 in CBC mode.

    To limit copies of the cleardata in memory, the complete blocks are encrypted directly
    from ``cleardata`` and only the last (partial) block goes through the PKCS7 padder.

    .. warning::

        This function does not authenticate the data. An HMAC of the ``iv`` and the returned
        ``cipherdata`` MUST be computed (Encrypt-then-MAC) before storing or sending it.

    .. warning::

        The ``iv`` must be freshly generated with a CSPRNG for every encryption
        (see :func:`pyaescbc.random_iv`) and never reused with the same key.

    .. seealso::

        function :func:`pyaescbc.derive_key` to create the derived key.

    .. note::

        The cleardata, aes_key and iv must be bytearrays.

    Parameters
    ----------
    cleardata : bytearray
        The message to encrypt using AES in CBC mode.

    aes_key : bytearray
        The 32-byte AES key.

    iv : bytearray
        The 16-byte initialization vector (IV) to use in AES-CBC mode.

    Returns
    -------
    cipherdata : bytearray
        The encrypted message. Its length is a positive multiple of 16.

    Raises
    ------
    TypeError
        If a given argument is not a ``bytearray`` instance.
    ValueError
        If the ``aes_key`` isn't 32 bytes long or the ``iv`` isn't 16 bytes long.
    """
    # Check the types of the parameters
    if not isinstance(cleardata, bytearray):
        raise TypeError('Parameter cleardata is not bytearray instance.')
    if not isinstance(aes_key, bytearray):
        raise TypeError('Parameter aes_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')

    # Check the values of the parameters (never include the values in the messages)
    if len(aes_key) != 32:
        raise ValueError('Parameter aes_key must be 32 bytes long.')
    if len(iv) != 16:
        raise ValueError('Parameter iv must be 16 bytes long.')

    last_block = None
    try:
        cipher = ciphers.Cipher(ciphers.algorithms.AES256(aes_key), ciphers.modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Encrypt all complete blocks directly from cleardata (no copy of the cleardata)
        full_len = len(cleardata) - (len(cleardata) % 16)
        cipherdata = bytearray(encryptor.update(memoryview(cleardata)[:full_len]))

        # Pad only the remaining 0-15 bytes into a mutable 16-byte block
        padder = padding.PKCS7(128).padder()
        last_block = bytearray(padder.update(memoryview(cleardata)[full_len:]))
        last_block += padder.finalize()

        # Encrypt the last block
        cipherdata += encryptor.update(last_block)
        cipherdata += encryptor.finalize()
        return cipherdata

    finally:
        if last_block is not None:
            delete_bytearray(last_block)