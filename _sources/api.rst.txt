API Reference
=============

The package ``pyaescbc`` is composed of the following functions, classes, and constants.

To learn how to use the package effectively, refer to the documentation :doc:`../usage`.

Encryption / Decryption
-----------------------

The high-level functions to encrypt and decrypt data, the exception raised when
authentication fails, and the function to erase sensitive data from memory.

.. autofunction:: pyaescbc.encrypt

.. autofunction:: pyaescbc.decrypt

.. autoclass:: pyaescbc.AuthError
    :members:

.. autofunction:: pyaescbc.delete_bytearray

.. autodata:: pyaescbc.DEFAULT_ITERATIONS

Encrypted Bundle Format
-----------------------

An encrypted bundle (format version 2) has the following structure
(all integers are big-endian):

.. code-block:: text

    offset  size   field
    0       4      magic       b"PACB"
    4       1      version     2
    5       4      iterations  uint32
    9       32     salt
    41      16     iv
    --------------------------- header (57 bytes, authenticated by the HMAC)
    57      32     hmac        HMAC-SHA256
    89      16*n   cipherdata  AES-256-CBC, PKCS7 padding

The keys are derived as follows:

.. code-block:: text

    master_key = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
    aes_key    = HKDF-Expand-SHA256(master_key, "pyaescbc v2 aes-256-cbc key", 32)
    hmac_key   = HKDF-Expand-SHA256(master_key, "pyaescbc v2 hmac-sha256 key", 32)

The HMAC authenticates each field prefixed by its length (8-byte big-endian):

.. code-block:: text

    hmac = HMAC-SHA256(hmac_key, len(header)     || header
                              || len(cipherdata) || cipherdata
                              || len(authdata)   || authdata)

Low-Level Components
--------------------

The lower-level building blocks used internally by :func:`pyaescbc.encrypt` and
:func:`pyaescbc.decrypt` (key derivation, HMAC creation and verification, bundle
packing/unpacking, and random data generation). Most users will not need to call
these directly.

.. note::

    The raw AES-CBC functions are internal and intentionally not part of the public API:
    decrypting unauthenticated data exposes a padding oracle. Use :func:`pyaescbc.encrypt`
    and :func:`pyaescbc.decrypt` instead.

.. autodata:: pyaescbc.__version__

Key derivation
~~~~~~~~~~~~~~

.. autofunction:: pyaescbc.derive_key

.. autodata:: pyaescbc.MIN_ITERATIONS

.. autodata:: pyaescbc.MAX_ITERATIONS

Authentication
~~~~~~~~~~~~~~

.. autofunction:: pyaescbc.create_hmac

.. autofunction:: pyaescbc.check_hmac

Bundle packing / unpacking
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pyaescbc.create_bundle_header

.. autofunction:: pyaescbc.create_encrypted_bundle

.. autofunction:: pyaescbc.extract_cryptography_components

.. autoclass:: pyaescbc.BundleComponents
    :members:

Random data generation
~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pyaescbc.random_bytearray

.. autofunction:: pyaescbc.random_iv

.. autofunction:: pyaescbc.random_salt