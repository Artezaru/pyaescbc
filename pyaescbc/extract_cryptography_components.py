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

from typing import Tuple

def extract_cryptography_components(encrypted_bundle: bytearray) -> Tuple[bytearray, bytearray, bytearray, bytearray]:
    """
    Extracts the IV, salt, expected HMAC, and cipherdata from the encrypted bundle.

    .. seealso::

        - function :func:`pyaescbc.create_encrypted_bundle` to create the encrypted bundle.

    Parameters
    ----------
    encrypted_bundle : bytearray
        The encrypted bundle. Must contain at least 80 bytes.

    Returns
    -------
    tuple
        A tuple containing the IV, salt, expected HMAC, and cipherdata.

    Raises
    ------
    TypeError
        If the argument is not a `bytearray` instance.
    ValueError
        If the bytearray does not contain at least 80 bytes.
    """
    # Check the types of the parameters
    if not isinstance(encrypted_bundle, bytearray):
        raise TypeError('Parameter encrypted_bundle is not bytearray instance.')
    
    # Check the value of the parameters
    if len(encrypted_bundle) < 80:
        raise ValueError(f'encrypted_bundle does not contain more than 80 bytes.') 

    # Extract the components
    iv = encrypted_bundle[0:16]
    salt = encrypted_bundle[16:48]
    expected_hmac = encrypted_bundle[48:80]
    cipherdata = encrypted_bundle[80:]
    return iv, salt, expected_hmac, cipherdata
