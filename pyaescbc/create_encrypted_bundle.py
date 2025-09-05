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

def create_encrypted_bundle(iv: bytearray, salt: bytearray, expected_hmac: bytearray, cipherdata: bytearray) -> bytearray:
    """
    Creates a bytearray containing all the information needed to decrypt the data.

    The encrypted bundle is composed by the initialization vector (IV), the salt, the expected HMAC and the cipherdata.

    .. seealso::

        - function :func:`pyaescbc.extract_cryptography_components` to extract the components from the encrypted bundle.

    Parameters
    ----------
    iv : bytearray
        The 16-byte initialization vector used for encryption.

    salt : bytearray
        The 32-byte salt used to generate the derived key.

    expected_hmac : bytearray
        The 32-byte expected HMAC.

    cipherdata : bytearray
        The encrypted message.

    Returns
    -------
    encrypted_bundle : bytearray
        The concatenated bytearray containing `iv + salt + expected_hmac + cipherdata`.

    Raises
    ------
    TypeError
        If any argument is not a `bytearray` instance.
    ValueError
        If any of the components (salt, iv, hmac) are not the correct length.
    """
    # Check the types of the parameters
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')
    if not isinstance(salt, bytearray):
        raise TypeError('Parameter salt is not bytearray instance.')
    if not isinstance(expected_hmac, bytearray):
        raise TypeError('Parameter expected_hmac is not bytearray instance.')
    if not isinstance(cipherdata, bytearray):
        raise TypeError('Parameter cipherdata is not bytearray instance.')
    
    # Check the values of the parameters
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.') 
    if len(salt) != 32:
        raise ValueError(f'{salt=} is not 32 bytes long.') 
    if len(expected_hmac) != 32:
        raise ValueError(f'{expected_hmac=} is not 32 bytes long.')

    # Create the encrypted bundle
    return iv + salt + expected_hmac + cipherdata
