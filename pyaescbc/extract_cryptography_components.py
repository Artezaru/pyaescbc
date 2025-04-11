def extract_cryptography_components(encrypted_bundle: bytearray) -> (bytearray, bytearray, bytearray, bytearray):
    """
    Extracts the IV, salt, expected HMAC, and cipherdata from the encrypted bundle.

    .. seealso::
        - function :func:`pyaescbc.create_encrypted_bundle` to create the encrypted bundle.

    Parameters
    ----------
    encrypted_bundle : bytearray
        The encrypted bundle. Must contain at least 80 bytes.

    Returns
    -------
    tuple
        A tuple containing the IV, salt, expected HMAC, and cipherdata.

    Raises
    ------
    TypeError
        If the argument is not a `bytearray` instance.
    ValueError
        If the bytearray does not contain at least 80 bytes.
    """
    if not isinstance(encrypted_bundle, bytearray):
        raise TypeError('Parameter encrypted_bundle is not bytearray instance.')
    if len(encrypted_bundle) < 80:
        raise ValueError(f'encrypted_bundle does not contain more than 80 bytes.') 

    iv = encrypted_bundle[0:16]
    salt = encrypted_bundle[16:48]
    expected_hmac = encrypted_bundle[48:80]
    cipherdata = encrypted_bundle[80:]
    return iv, salt, expected_hmac, cipherdata
