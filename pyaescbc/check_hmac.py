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
