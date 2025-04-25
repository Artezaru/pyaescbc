Usage
==============

Package usage
-------------

To encrypt a message, use the following code, available in the `examples` directory of the package:

.. literalinclude:: ../../examples/encrypt.py

The iteration can also be generated randomly, using :func:`pyaescbc.generate_random_iterations`.

Type convertion
-----------------

If your clear data is a string, you can convert them to bytearray using the following code:

.. code-block:: python

    # Convert a string to bytearray
    string = "Hello, World!"
    byte_array = bytearray(string, 'utf-8')

Similarly, after decrypting, you can convert the bytearray back to a string using the following code:

.. code-block:: python

    # Convert a bytearray to string
    decrypted_string = byte_array.decode('utf-8')
    print(decrypted_string)  # Output: Hello, World!

For encrypted data (ie the ``encrypted_bundle``), the type is a bytearray but it can't be converted to a string using ``utf-8``.
This is because the encrypted data is not a valid UTF-8 string.

I recommend to save the encrypted data in a file or a database as a bytearray, and then read it back as a bytearray when you need to decrypt it.

Otherwise, you can convert the bytearray to a base64 string using the following code:

.. code-block:: python

    import base64

    # Convert bytearray to base64 string
    encrypted_bundle = bytearray(b'\x00\x01\x02\x03')
    base64_string = base64.b64encode(encrypted_bundle).decode('utf-8')
    print(base64_string) 

The base64 string can be saved in a file or a database as a string, and then read it back as a base64 string when you need to decrypt it.
To reconvert the base64 string to a bytearray, you can use the following code:

.. code-block:: python

    # Convert base64 string to bytearray
    base64_string = "AAECAw=="
    encrypted_bundle = bytearray(base64.b64decode(base64_string))
    print(encrypted_bundle) 