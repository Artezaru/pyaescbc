Welcome to pyaescbc's documentation!
=========================================================================================

Description of the package
--------------------------

AES-CBC encryption tools based on crytography package !

The package `pyaescbc` provides functions to encrypt and decrypt data using the AES-CBC encryption mode. 
The package is written in Python and uses the `cryptography` library for the AES encryption and decryption. 
The package also provides functions to generate a derived key from a password and a pin, and to create an HMAC value from the derived key, IV, and ciphertext. 
The package is designed to be easy to use and secure, and it is suitable for encrypting sensitive data.

The encryption process is designed as follow :

.. image:: ../../pyaescbc/resources/encrypt.png
    :align: center

The decryption process is designed as follow :

.. image:: ../../pyaescbc/resources/decrypt.png
    :align: center

Contents
--------

The documentation is divided into the following sections:

- **Installation**: This section describes how to install the package.
- **API Reference**: This section contains the documentation of the package's API.
- **Usage**: This section contains the documentation of how to use the package.

.. toctree::
   :maxdepth: 1
   :caption: Contents:

   ./installation
   ./api
   ./usage


Author
------

The package ``pyaescbc`` was created by the following authors:

- Artezaru <artezaru.github@proton.me>

You can access the package and the documentation with the following URL:

- **Git Plateform**: https://github.com/Artezaru/pyaescbc.git
- **Online Documentation**: https://Artezaru.github.io/pyaescbc

License
-------

Please refer to the [LICENSE] file for the license of the package.
