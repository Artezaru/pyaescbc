# Copyright 2025 Artezaru
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Key mode: ``PACK`` bundles, encrypted with a random 32-byte key (no key derivation).

**Internal: no stability guarantee.** Use ``pyaescbc.encrypt_with_key``,
``pyaescbc.decrypt_with_key`` and ``pyaescbc.generate_key``.

The key mode is meant for envelope encryption: a random data key encrypts many small
messages in microseconds, and the data key itself is stored encrypted with a password
using the password mode (one slow derivation per session instead of one per message).

Bundle format, key format version 1 (all integers are big-endian)::

    offset  size  field
    0       4     magic       b"PACK"
    4       1     version     1
    5       16    iv
    ------------------------- header (21 bytes, authenticated by the HMAC)
    21      32    hmac
    53      16*n  cipherdata  (n >= 1)

Modules
-------
expand_key
    Key generation and HKDF expansion: key -> AES key and HMAC key.
create_key_bundle
    Format constants, header creation and bundle assembly.
extract_key_bundle_components
    Bundle parsing and structural validation.
cleardata_to_key_bundle
    Encryption (``pyaescbc.encrypt_with_key``).
key_bundle_to_cleardata
    Decryption (``pyaescbc.decrypt_with_key``).

This package depends only on ``_common``, never on another mode.
"""

__all__: list[str] = []
