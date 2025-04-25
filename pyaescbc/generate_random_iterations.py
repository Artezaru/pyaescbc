import random
from typing import Optional

def generate_random_iterations(Nmin: Optional[int] = None, Nmax: Optional[int] = None) -> int:
    """
    Generates a random number of iterations for PBKDF2.

    The number of iterations is randomly generated between `Nmin` and `Nmax`.

    Use the following code to estimate the order of magnitude of the number of iterations.
    By default, the number of iterations is between 2,000,000 and 5,000,000 (valid for computers with 4GB of RAM in 2021).
    It is recommended to have a derived key generation time between 1 and 2 seconds to avoid brute force attacks withouth affecting the user experience.

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
    Nmin : Optional[int], optional
        The minimum number of iterations. The default is None -> 2,000,000.

    Nmax : Optional[int]
        The maximum number of iterations. The default is None -> 5,000,000.

    Returns
    -------
    iterations : int
        The random number of iterations.

    Raises
    ------
    TypeError
        If `Nmin` or `Nmax` are not int instances.
    ValueError
        If `Nmin` or `Nmax` are not positive integers or if `Nmin` is greater than `Nmax`.
    """
    # Check the types of the parameters
    if (Nmin is not None) and (not isinstance(Nmin, int)):
        raise TypeError('Parameter Nmin is not int instance.')
    if (Nmax is not None) and (not isinstance(Nmax, int)):
        raise TypeError('Parameter Nmax is not int instance.')
    
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

    # Generate a random number of iterations
    return random.randint(Nmin, Nmax)