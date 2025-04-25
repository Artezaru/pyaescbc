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