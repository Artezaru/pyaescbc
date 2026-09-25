# pyaescbc

## Description

AES-CBC encryption tools based on crytography package !

The package `pyaescbc` provides functions to encrypt and decrypt data using the AES-CBC encryption mode. The package is written in Python and uses the `cryptography` library for the AES encryption and decryption. The package also provides functions to create an HMAC value from the derived key, IV, and ciphertext. The package is designed to be easy to use.

## Security considerations

> [!WARNING]
> **Consider AES-GCM for new projects.**
> `pyaescbc` implements AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC). This construction
> is secure when assembled correctly, but it requires several hand-assembled parts
> (padding, HMAC, key separation, constant-time comparison).
> For new projects, prefer an authenticated encryption mode (AEAD) such as
> [`AESGCM`](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
> or [`ChaCha20Poly1305`](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305)
> from the `cryptography` library, which provide confidentiality and integrity in a single primitive.
>
> **Memory wiping is best-effort.** Python cannot guarantee that secrets are erased from memory
> (immutable copies may be created by the interpreter or by the underlying libraries).

## Usage

General usage of the package includes:

``` python
import pyaescbc

# Encryption
cleardata = bytearray("Hello, World!", 'utf-8')
password = bytearray("password", 'utf-8')
iterations = 2_000_000
authdata = bytearray("user=toto", 'utf-8') # Optional authentication data (can be None)
encrypted_bundle = pyaescbc.encrypt(cleardata, password, iterations=iterations, authdata=authdata, delete_keys=True, delete_data=True)

# Decryption
password = bytearray("password", 'utf-8')
authdata = bytearray("user=toto", 'utf-8') # Optional authentication data (can be None)
decrypted_data = pyaescbc.decrypt(encrypted_bundle, password, authdata=authdata, delete_keys=True)

print(decrypted_data)
```

![Encryption Process](https://raw.githubusercontent.com/Artezaru/pyaescbc/master/pyaescbc/resources/encrypt.png)

![Decryption Process](https://raw.githubusercontent.com/Artezaru/pyaescbc/master/pyaescbc/resources/decrypt.png)

## Authors

- Artezaru <artezaru.github@proton.me>

- **Git Plateform**: https://github.com/Artezaru/pyaescbc.git
- **Online Documentation**: https://Artezaru.github.io/pyaescbc

## Installation

Install with pip

```
pip install pyaescbc
```

```
pip install git+https://github.com/Artezaru/pyaescbc.git
```

Clone with git

```
git clone https://github.com/Artezaru/pyaescbc.git
```

## License

Copyright 2025 Artezaru

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

