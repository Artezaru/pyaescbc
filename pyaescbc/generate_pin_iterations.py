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

import hashlib
from typing import Optional

from .delete_bytearray import delete_bytearray

def generate_pin_iterations(pin: bytearray, Nmin: Optional[int] = None, Nmax: Optional[int] = None, delete_keys: bool = True) -> int:
    """
    Generates a number of iterations for PBKDF2 based on the PIN.

    Use the following code to estimate the order of magnitude of the number of iterations.
    By default, the number of iterations is between 2,000,000 and 5,000,000 (valid for computers with 4GB of RAM in 2021).
    It is recommended to have a derived key generation time between 1 and 2 seconds to avoid brute force attacks withouth affecting the user experience.

    .. note::

        The PIN is deleted from memory at the end of the function if delete_keys is True.
        Otherwise, it needs to be deleted after dealing with Exception.

    .. code-block:: python

        import pyaescbc
        import time
        import os

        password = pyaescbc.random_bytearray(32)
        salt = pyaescbc.random_salt()

        time_start = time.time()
        iteration = 2_000_000 # Change this value to the estimated number of iterations.
        pyaescbc.derive_key(password, salt, iteration)
        time_end = time.time()
        print(f'{iteration=}, {time_end-time_start=}')

    Parameters
    ----------
    pin : bytearray
        The PIN to generate the number of iterations.

    Nmin : Optional[int], optional
        The minimum number of iterations. The default is None -> 2,000,000.

    Nmax : Optional[int]
        The maximum number of iterations. The default is None -> 5,000,000.

    delete_keys : bool
        Delete the PIN from memory at the end of the function. Default is True.
        If False, it needs to be deleted after dealing with Exception.

    Returns
    -------
    iterations : int
        The number of iterations based on the PIN.

    Raises
    ------
    TypeError
        If `Nmin` or `Nmax` are not int instances or if `pin` is not a bytearray instance.
    ValueError
        If `Nmin` or `Nmax` are not positive integers or if `Nmin` is greater than `Nmax`.
    """
    # Check the types of the parameters
    if not isinstance(pin, bytearray):
        raise TypeError('Parameter pin is not bytearray instance.')
    if (Nmin is not None) and (not isinstance(Nmin, int)):
        raise TypeError('Parameter Nmin is not int instance.')
    if (Nmax is not None) and (not isinstance(Nmax, int)):
        raise TypeError('Parameter Nmax is not int instance.')
    if not isinstance(delete_keys, bool):
        raise TypeError('Parameter delete_keys is not a boolean.')
    
    if Nmin is None:
        Nmin = 2_000_000
    if Nmax is None:
        Nmax = 5_000_000
    
    # Check the values of the parameters
    if Nmin <= 0:
        raise ValueError('Parameter Nmin must be a positive integer.')
    if Nmax <= 0:
        raise ValueError('Parameter Nmax must be a positive integer.')
    if Nmin >= Nmax:
        raise ValueError('Parameter Nmin must be less than Nmax.')

    # Hash the PIN to generate a random number
    pin_hash = hashlib.sha256(pin).digest()
    hash_value = int.from_bytes(pin_hash, byteorder='big')

    # Generate the number of iterations
    iterations = hash_value % (Nmax - Nmin + 1) + Nmin

    # Delete the PIN from memory if required
    if delete_keys:
        delete_bytearray(pin)

    return iterations