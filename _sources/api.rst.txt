API Reference
==============

The package ``pyaescbc`` is composed of the following functions, classes, and modules.

To learn how to use the package effectively, refer to the documentation :doc:`../usage`.

Encryption / Decryption
------------------------

The high-level functions to encrypt and decrypt data, and to securely erase sensitive
data from memory once it is no longer needed.

.. autofunction:: pyaescbc.encrypt

.. autofunction:: pyaescbc.decrypt

.. autofunction:: pyaescbc.delete_bytearray

Iterations Generation
-----------------------

Helpers to generate the number of PBKDF2 iterations used to derive the encryption keys,
either randomly or from a user PIN.

.. autofunction:: pyaescbc.generate_random_iterations

.. autofunction:: pyaescbc.generate_pin_iterations

Low-Level Components
----------------------

The lower-level building blocks used internally by :func:`pyaescbc.encrypt` and
:func:`pyaescbc.decrypt` (key derivation, raw AES-CBC encryption, HMAC creation and
verification, bundle packing/unpacking, and random data generation). Most users will not
need to call these directly.

.. autodata:: pyaescbc.__version__

.. autofunction:: pyaescbc.derive_key

.. autofunction:: pyaescbc.encrypt_AES_CBC

.. autofunction:: pyaescbc.decrypt_AES_CBC

.. autofunction:: pyaescbc.create_encrypted_bundle

.. autofunction:: pyaescbc.extract_cryptography_components

.. autofunction:: pyaescbc.random_bytearray

.. autofunction:: pyaescbc.random_iv

.. autofunction:: pyaescbc.random_salt

.. autofunction:: pyaescbc.create_hmac

.. autofunction:: pyaescbc.check_hmac

.. autoclass:: pyaescbc.AuthError
    :members: