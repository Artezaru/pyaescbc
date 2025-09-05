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

import hmac
import hashlib
from typing import Optional

def create_hmac(hmac_key: bytearray, iv: bytearray, cipherdata: bytearray, authdata: Optional[bytearray] = None) -> bytearray:
    """
    Creates the expected HMAC using the hmac_key on the iv, cipherdata, and optional auth_data.
    The HMAC is created using the SHA-256 hash function. The HMAC is used to verify the integrity of the encrypted message.
    The hmac_key is extracted from the derived key, which is created using PBKDF2HMAC.

    .. code-block:: console

        HMAC = HMAC(key, SHA256(iv + cipherdata + authdata))

    .. seealso::

        -function :func:`pyaescbc.derive_key` to create the derived key.

    Parameters
    ----------
    hmac_key : bytearray
        The 32-byte long key used to create the HMAC. It is extracted from the derived key.

    iv : bytearray
        The 16-byte long initialization vector used for encryption.

    cipherdata : bytearray
        The encrypted message.

    authdata : Optional[bytearray]
        Optional additional authentication data. If provided, it is prepended to the HMAC input.

    Returns
    -------
    expected_hmac : bytearray
        The 32-byte expected HMAC value.

    Raises
    ------
    TypeError
        If any argument is not a `bytearray` instance.

    ValueError
        If the hmac_key isn't 32 bytes, the IV isn't 16 bytes.
    """
    # Check the types of the parameters
    if not isinstance(hmac_key, bytearray):
        raise TypeError('Parameter hmac_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')
    if not isinstance(cipherdata, bytearray):
        raise TypeError('Parameter cipherdata is not bytearray instance.')
    if authdata is not None and not isinstance(authdata, bytearray):
        raise TypeError('Parameter authdata is not bytearray instance.')
    
    # Check the value of the parameters
    if len(hmac_key) != 32:
        raise ValueError(f'{hmac_key=} is not 32 bytes long.') 
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.')

    # Create the HMAC
    if authdata is None:
        authdata = bytearray()
    expected_hmac = bytearray(hmac.new(hmac_key, iv + cipherdata + authdata, hashlib.sha256).digest())

    return expected_hmac
