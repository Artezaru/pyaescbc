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

def check_hmac(given_hmac: bytearray, expected_hmac: bytearray) -> bool:
    """
    Verifies if the derived 32-byte given HMAC matches the expected HMAC.

    Parameters
    ----------
    given_hmac : bytearray
        The 32-byte long HMAC to verify.

    expected_hmac : bytearray
        The 32-byte long expected HMAC.

    Returns
    -------
    bool
        True if the HMACs match, False otherwise.
    
    Raises
    ------
    TypeError
        If any argument is not a `bytearray` instance.
    ValueError
        If the given_hmac or expected_hmac isn't 32 bytes.
    """
    # Check the types of the parameters
    if not isinstance(given_hmac, bytearray):
        raise TypeError('Parameter given_hmac is not bytearray instance.')
    if not isinstance(expected_hmac, bytearray):
        raise TypeError('Parameter expected_hmac is not bytearray instance.')

    # Check the value of the parameters
    if len(given_hmac) != 32:
        raise ValueError(f'{given_hmac=} is not 32 bytes long.') 
    if len(expected_hmac) != 32:
        raise ValueError(f'{expected_hmac=} is not 32 bytes long.') 

    # Compare the HMACs
    result = hmac.compare_digest(given_hmac, expected_hmac)

    return result
