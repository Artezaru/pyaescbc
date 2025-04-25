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