Usage
=====

All data, passwords and keys are ``bytearray`` objects, so that they can be wiped from memory
after use (see :ref:`wiping`).

Password mode
-------------

To encrypt data with a password, use :func:`pyaescbc.encrypt` and :func:`pyaescbc.decrypt`.
This example is available in the ``examples`` directory of the repository:

.. literalinclude:: ../../examples/encrypt.py
    :language: python

- ``iterations`` sets the cost of the PBKDF2 key derivation: :data:`pyaescbc.DEFAULT_ITERATIONS`
  (600 000) by default, between :data:`pyaescbc.MIN_ITERATIONS` (100 000) and
  :data:`pyaescbc.MAX_ITERATIONS` (100 000 000). It is stored in the bundle, so it is not needed
  to decrypt. A higher value makes brute-force attacks slower, but also every call.
- ``authdata`` (optional, keyword-only) is authenticated but neither encrypted nor stored: the
  same value must be given to decrypt. It binds the data to a context (a user, a record, a field).

Key mode: encrypting many secrets
---------------------------------

The password mode runs a slow key derivation on every call, by design. To encrypt many small
secrets (e.g. the entries of a password manager), use a random **data key** with
:func:`pyaescbc.encrypt_with_key` and :func:`pyaescbc.decrypt_with_key`, and protect that data
key once with the password ("envelope encryption"):

.. literalinclude:: ../../examples/encrypt_with_key.py
    :language: python

- The slow derivation runs once per session (to unwrap the data key), not once per secret.
- Changing the password only re-wraps the data key: the secrets are not re-encrypted.
- To make an old password useless even against old copies of the data, generate a new data
  key and re-encrypt the secrets with it: this is fast in key mode.
- ``authdata`` can bind each secret to its location (e.g. ``"entry=42"``), so that a
  ciphertext cannot be moved to another entry unnoticed.

.. warning::

    The key must come from :func:`pyaescbc.generate_key`. Never use a password as key: it
    would get no brute-force protection.

Handling errors
---------------

.. code-block:: python

    import pyaescbc

    try:
        cleardata = pyaescbc.decrypt(encrypted_bundle, password)
    except pyaescbc.AuthError:
        ...  # wrong password or authdata, or the bundle has been tampered with
    except ValueError:
        ...  # not a valid bundle (wrong size, unknown format or version, bundle of the other mode)

:class:`pyaescbc.AuthError` covers every authentication failure on purpose: a wrong password,
a wrong ``authdata`` and a modified bundle cannot be told apart. A ``ValueError`` is raised
before any key derivation when the bundle is malformed, or when a bundle of one mode is given to
the other mode (for example: *"this is a key-mode bundle, use decrypt_with_key()"*).

.. _wiping:

Wiping secrets from memory
--------------------------

By default:

- :func:`pyaescbc.encrypt` wipes ``cleardata`` and ``password`` once the encryption succeeded;
- :func:`pyaescbc.decrypt` wipes ``password``;
- :func:`pyaescbc.encrypt_with_key` wipes ``cleardata`` but keeps ``key`` (reused for many
  messages);
- :func:`pyaescbc.decrypt_with_key` keeps ``key``.

Use ``delete_keys`` and ``delete_data`` to change this behaviour. The clear data and the bundle
are never wiped when the operation fails (for example after a mistyped password), so that the
call can be retried. Use :func:`pyaescbc.delete_bytearray` to wipe your own secrets, such as
the decrypted data once used:

.. code-block:: python

    cleardata = pyaescbc.decrypt(encrypted_bundle, password)
    ...  # use cleardata
    pyaescbc.delete_bytearray(cleardata)  # cleardata == bytearray()

.. note::

    Wiping is best-effort: Python and the underlying libraries may keep immutable copies of
    sensitive data, which cannot be erased.

Type conversion
---------------

If your clear data is a string, convert it to a ``bytearray`` before encrypting it:

.. code-block:: python

    cleardata = bytearray("Hello, World!", "utf-8")

After decrypting, convert the ``bytearray`` back to a string:

.. code-block:: python

    text = cleardata.decode("utf-8")
    print(text)  # Hello, World!

Storing a bundle
----------------

An encrypted bundle is binary data: it is not valid UTF-8 and cannot be decoded as text. Store
it as bytes in a file or a database, and read it back as a ``bytearray``:

.. code-block:: python

    from pathlib import Path

    Path("secret.bin").write_bytes(encrypted_bundle)
    encrypted_bundle = bytearray(Path("secret.bin").read_bytes())

To store it as text (JSON, a text column, a configuration file...), encode it in base64:

.. code-block:: python

    import base64

    text = base64.b64encode(encrypted_bundle).decode("ascii")   # bytearray -> str
    encrypted_bundle = bytearray(base64.b64decode(text))         # str -> bytearray