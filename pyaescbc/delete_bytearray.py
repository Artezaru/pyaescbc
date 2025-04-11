import os

def delete_bytearray(barray: bytearray) -> None:
    """
    Securely overwrites the contents of a bytearray and deletes the object from memory.

    Parameters
    ----------
    barray : bytearray
        The bytearray to securely delete from memory.

    Raises
    ------
    TypeError
        If the given argument is not a `bytearray` instance.
    """
    if not isinstance(barray, bytearray):
        raise TypeError('Parameter barray is not bytearray instance.')
    
    for index in range(len(barray)):
        barray[index] = os.urandom(1)[0]  # Overwrite with random data
    barray.clear()  # Clear contents