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

def decrypt_AES_CBC(cipherdata: bytearray, aes_key: bytearray, iv: bytearray) -> bytearray:
    """
    Decrypts a cipherdata message using AES-256 in CBC mode.

    The data is decrypted using AES-256 in CBC mode and then unpadded using PKCS7 padding.

    .. warning::

        This function does not authenticate the data. The HMAC of the ``iv`` and
        ``cipherdata`` MUST be verified (constant-time comparison) BEFORE calling this
        function. Decrypting unauthenticated data exposes a padding oracle.

    .. seealso::

        function :func:`pyaescbc.derive_key` to create the derived key.

    .. note::

        The cipherdata, aes_key and iv must be bytearrays.

    Parameters
    ----------
    cipherdata : bytearray
        The encrypted message to decrypt. Its length must be a positive multiple of 16.

    aes_key : bytearray
        The 32-byte AES key.

    iv : bytearray
        The 16-byte initialization vector (IV) used in AES-CBC mode.

    Returns
    -------
    cleardata : bytearray
        The decrypted clear message.

    Raises
    ------
    TypeError
        If a given argument is not a ``bytearray`` instance.
    ValueError
        If the ``aes_key`` isn't 32 bytes long, the ``iv`` isn't 16 bytes long,
        the ``cipherdata`` length isn't a positive multiple of 16, or the padding is invalid.
    """
    # Check the types of the parameters
    if not isinstance(cipherdata, bytearray):
        raise TypeError('Parameter cipherdata is not bytearray instance.')
    if not isinstance(aes_key, bytearray):
        raise TypeError('Parameter aes_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')

    # Check the values of the parameters (never include the values in the messages)
    if len(aes_key) != 32:
        raise ValueError('Parameter aes_key must be 32 bytes long.')
    if len(iv) != 16:
        raise ValueError('Parameter iv must be 16 bytes long.')
    if len(cipherdata) == 0 or len(cipherdata) % 16 != 0:
        raise ValueError('Parameter cipherdata length must be a positive multiple of 16.')

    buffer = None
    try:
        # Decrypt directly into a mutable buffer (no immutable copy of the padded cleardata)
        cipher = ciphers.Cipher(ciphers.algorithms.AES256(aes_key), ciphers.modes.CBC(iv))
        decryptor = cipher.decryptor()
        buffer = bytearray(len(cipherdata) + 15)  # size required by update_into
        written = decryptor.update_into(cipherdata, buffer)
        decryptor.finalize()

        # Remove the PKCS7 padding (raises ValueError if invalid)
        unpadder = padding.PKCS7(128).unpadder()
        cleardata = bytearray(unpadder.update(memoryview(buffer)[:written]))
        cleardata += unpadder.finalize()
        return cleardata

    finally:
        if buffer is not None:
            delete_bytearray(buffer)