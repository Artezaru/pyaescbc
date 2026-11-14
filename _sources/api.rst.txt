API Reference
=============

The public API of ``pyaescbc`` consists of the functions, classes and constants listed on this
page (they are the names exported in ``pyaescbc.__all__``). Everything else is internal and may
change in any release.

To learn how to use the package, refer to :doc:`../usage`.

Password mode
-------------

Encryption with a password. The key is derived with PBKDF2-HMAC-SHA256 on every call: slow on
purpose, to resist brute-force attacks. Produces ``PACB`` bundles.

.. autofunction:: pyaescbc.encrypt

.. autofunction:: pyaescbc.decrypt

.. autodata:: pyaescbc.DEFAULT_ITERATIONS
    :annotation: = 600000

    Default number of PBKDF2 iterations (OWASP recommendation for PBKDF2-HMAC-SHA256).

.. autodata:: pyaescbc.MIN_ITERATIONS
    :annotation: = 100000

    Minimum number of PBKDF2 iterations accepted (prevents weak settings).

.. autodata:: pyaescbc.MAX_ITERATIONS
    :annotation: = 100000000

    Maximum number of PBKDF2 iterations accepted (prevents denial of service when the
    iteration count is read from an untrusted bundle).

Key mode
--------

Encryption with a random 32-byte key, without key derivation: each call takes microseconds.
Meant for envelope encryption (many secrets protected by a random data key, the data key itself
protected by a password with :func:`pyaescbc.encrypt`). Produces ``PACK`` bundles.

.. warning::

    The key must come from :func:`pyaescbc.generate_key`. Never use a password as key: it
    would get no brute-force protection. Use the password mode for passwords.

.. autofunction:: pyaescbc.encrypt_with_key

.. autofunction:: pyaescbc.decrypt_with_key

.. autofunction:: pyaescbc.generate_key

.. autodata:: pyaescbc.KEY_SIZE
    :annotation: = 32

    Size in bytes of a key-mode key.

Both modes
----------

.. autoclass:: pyaescbc.AuthError
    :members:

.. autofunction:: pyaescbc.delete_bytearray

.. autodata:: pyaescbc.__version__

Deprecated names
----------------

The low-level building blocks that were public in pyaescbc 2.1 and earlier are now internal:
``cleardata_to_encrypted_bundle``, ``encrypted_bundle_to_cleardata``, ``derive_key``,
``create_bundle_header``, ``create_encrypted_bundle``, ``extract_cryptography_components``,
``BundleComponents``, ``create_hmac``, ``check_hmac``, ``random_bytearray``, ``random_iv`` and
``random_salt``.

They can still be accessed as attributes of ``pyaescbc`` but emit a ``DeprecationWarning``,
and will be removed in the next major version. Use :func:`pyaescbc.encrypt`,
:func:`pyaescbc.decrypt`, :func:`pyaescbc.encrypt_with_key` and :func:`pyaescbc.decrypt_with_key`
instead.

Bundle formats
--------------

Both formats share the same layout: a format-specific header, the HMAC-SHA256 tag, then the
AES-256-CBC cipherdata (PKCS7 padding). All integers are big-endian.

The magic identifies the format: :func:`pyaescbc.decrypt` rejects key-mode bundles and
:func:`pyaescbc.decrypt_with_key` rejects password-mode bundles, with an explicit
``ValueError``, before any computation.

Password-mode bundle (``PACB``, format version 2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

The keys are derived from the password as follows:

.. code-block:: text

    master_key = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
    aes_key    = HKDF-Expand-SHA256(master_key, "pyaescbc v2 aes-256-cbc key", 32)
    hmac_key   = HKDF-Expand-SHA256(master_key, "pyaescbc v2 hmac-sha256 key", 32)

Key-mode bundle (``PACK``, format version 1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

    offset  size   field
    0       4      magic       b"PACK"
    4       1      version     1
    5       16     iv
    --------------------------- header (21 bytes, authenticated by the HMAC)
    21      32     hmac        HMAC-SHA256
    53      16*n   cipherdata  AES-256-CBC, PKCS7 padding

The keys are expanded from the 32-byte key, with labels distinct from the password mode
(the same 32 bytes never give the same keys in both modes):

.. code-block:: text

    aes_key    = HKDF-Expand-SHA256(key, "pyaescbc key-mode v1 aes-256-cbc key", 32)
    hmac_key   = HKDF-Expand-SHA256(key, "pyaescbc key-mode v1 hmac-sha256 key", 32)

There is no salt and no iteration count: the key is random, there is nothing to stretch.

HMAC (both formats)
~~~~~~~~~~~~~~~~~~~

The HMAC authenticates the whole header, the cipherdata and the optional ``authdata``, each
field prefixed by its length (8-byte big-endian), so that no byte can be moved from one field
to another:

.. code-block:: text

    hmac = HMAC-SHA256(hmac_key, len(header)     || header
                              || len(cipherdata) || cipherdata
                              || len(authdata)   || authdata)

The HMAC is verified in constant time before anything is decrypted. ``authdata`` is neither
encrypted nor stored in the bundle: the same value must be given to decrypt.