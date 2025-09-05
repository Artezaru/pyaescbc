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

from .random_bytearray import random_bytearray

def random_iv() -> bytearray:
    """
    Generates a random 16-byte initialization vector (IV) for AES encryption.

    Returns
    -------
    iv : bytearray
        A random 16-byte bytearray to be used as an IV.
    """
    return random_bytearray(16)