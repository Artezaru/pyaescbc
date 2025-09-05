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

import os

def random_bytearray(Nbytes: int) -> bytearray:
    """
    Generates a random bytearray of Nbytes length.

    Parameters
    ----------
    Nbytes : int
        The number of bytes of the random bytearray. Must be a positive integer.

    Returns
    -------
    barray : bytearray
        A random bytearray of length Nbytes.

    Raises
    ------
    TypeError
        If `Nbytes` is not an integer.
    ValueError
        If `Nbytes` is not a positive integer.
    """
    # Check if Nbytes is a positive integer
    if not isinstance(Nbytes, int):
        raise TypeError('Parameter Nbytes is not integer.')
    if Nbytes < 0:
        raise ValueError('Parameter Nbytes must be a positive integer.')
    
    return bytearray(os.urandom(Nbytes))