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
    Encrypts a message with AES-256 in CBC mode, with PKCS7 padding.

    .. code-block:: text

        cipherdata = AES-256-CBC(aes_key, iv, PKCS7(cleardata))

    Internal building block, not part of the public API: use ``pyaescbc.encrypt`` or
    ``pyaescbc.encrypt_with_key``, which authenticate the result.

    .. warning::

        This function does not authenticate the data. The caller MUST compute an HMAC
        over the bundle header (which contains the ``iv``) and the returned ``cipherdata``
        (Encrypt-then-MAC) before storing or sending it.

    .. warning::

        The ``iv`` must be freshly generated with a CSPRNG for every encryption
        (``random_iv()`` in ``pyaescbc._common.random``) and never reused with the same key.

    .. note::

        To limit copies of the clear data in memory, the complete 16-byte blocks are
        encrypted directly from ``cleardata``; only the last 0 to 15 bytes go through the
        PKCS7 padder. The padder returns immutable ``bytes``, so up to 15 bytes of clear
        data may remain in memory after the call (wiping is best-effort).

    Parameters
    ----------
    cleardata : bytearray
        The message to encrypt. It may be empty (one block of padding is then produced).
        It is not modified.

    aes_key : bytearray
        The 32-byte AES key. It is not modified.

    iv : bytearray
        The 16-byte initialization vector. It is not modified.

    Returns
    -------
    cipherdata : bytearray
        The encrypted message. Its length is a positive multiple of 16
        (``16 * (len(cleardata) // 16 + 1)``).

    Raises
    ------
    TypeError
        If an argument is not a ``bytearray`` instance.
    ValueError
        If ``aes_key`` is not 32 bytes long or ``iv`` is not 16 bytes long.
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
        # (the padder output itself is immutable bytes and cannot be wiped)
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



def decrypt_AES_CBC(cipherdata: bytearray, aes_key: bytearray, iv: bytearray) -> bytearray:
    r"""
    Decrypts a message encrypted with AES-256 in CBC mode, and removes the PKCS7 padding.

    .. code-block:: text

        cleardata = unPKCS7(AES-256-CBC-decrypt(aes_key, iv, cipherdata))

    Internal building block, not part of the public API: use ``pyaescbc.decrypt`` or
    ``pyaescbc.decrypt_with_key``, which verify the HMAC first.

    .. warning::

        This function does not authenticate the data. The caller MUST verify the HMAC of
        the bundle header (which contains the ``iv``) and of the ``cipherdata``, with a
        constant-time comparison, BEFORE calling this function. Decrypting
        unauthenticated data exposes a padding oracle.

    .. note::

        The data is decrypted into a mutable buffer, which is wiped at the end of the call.
        The PKCS7 unpadder, however, returns immutable ``bytes`` holding the clear data
        (except its last block): this copy cannot be wiped (wiping is best-effort).

    Parameters
    ----------
    cipherdata : bytearray
        The encrypted message. Its length must be a positive multiple of 16.
        It is not modified.

    aes_key : bytearray
        The 32-byte AES key. It is not modified.

    iv : bytearray
        The 16-byte initialization vector used for encryption. It is not modified.

    Returns
    -------
    cleardata : bytearray
        The decrypted message, without padding.

    Raises
    ------
    TypeError
        If an argument is not a ``bytearray`` instance.
    ValueError
        If ``aes_key`` is not 32 bytes long, ``iv`` is not 16 bytes long, the length of
        ``cipherdata`` is not a positive multiple of 16, or the padding is invalid
        (which cannot happen for authenticated data encrypted by :func:`encrypt_AES_CBC`).
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
        # Decrypt directly into a mutable buffer, wiped in the finally block
        cipher = ciphers.Cipher(ciphers.algorithms.AES256(aes_key), ciphers.modes.CBC(iv))
        decryptor = cipher.decryptor()
        buffer = bytearray(len(cipherdata) + 15)  # update_into needs len(data) + block_size - 1
        written = decryptor.update_into(cipherdata, buffer)
        decryptor.finalize()

        # Remove the PKCS7 padding (raises ValueError if invalid)
        # (the unpadder output is immutable bytes and cannot be wiped)
        unpadder = padding.PKCS7(128).unpadder()
        cleardata = bytearray(unpadder.update(memoryview(buffer)[:written]))
        cleardata += unpadder.finalize()
        return cleardata

    finally:
        if buffer is not None:
            delete_bytearray(buffer)
