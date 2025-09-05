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

def delete_bytearray(barray: bytearray) -> None:
    r"""
    Securely overwrites the contents of a bytearray and deletes the object from memory.

    .. code-block:: python

        import pyaescbc as aes
        import os

        # Create a bytearray
        barray = bytearray(os.urandom(32))  # Example: 32 random bytes

        # Securely delete the bytearray
        aes.delete_bytearray(barray)

    Parameters
    ----------
    barray : bytearray
        The bytearray to securely delete from memory.

    Raises
    ------
    TypeError
        If the given argument is not a `bytearray` instance.
    """
    # Check if the input is a bytearray
    if not isinstance(barray, bytearray):
        raise TypeError('Parameter barray is not bytearray instance.')
    
    # Delete the bytearray by overwriting its contents with random data
    for index in range(len(barray)):
        barray[index] = os.urandom(1)[0]  # Overwrite with random data
    barray.clear()  # Clear contents