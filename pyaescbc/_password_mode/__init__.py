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
Password mode: ``PACB`` bundles, encrypted with a key derived from a password.

**Internal: no stability guarantee.** Use ``pyaescbc.encrypt`` and ``pyaescbc.decrypt``.

Bundle format, version 2 (all integers are big-endian)::

    offset  size  field
    0       4     magic       b"PACB"
    4       1     version     2
    5       4     iterations  uint32
    9       32    salt
    41      16    iv
    ------------------------- header (57 bytes, authenticated by the HMAC)
    57      32    hmac
    89      16*n  cipherdata  (n >= 1)

Modules
-------
derive_key
    PBKDF2-HMAC-SHA256 + HKDF: password -> AES key and HMAC key.
create_encrypted_bundle
    Format constants, header creation and bundle assembly.
extract_cryptography_components
    Bundle parsing and structural validation (before any key derivation).
cleardata_to_encrypted_bundle
    Encryption (``pyaescbc.encrypt``).
encrypted_bundle_to_cleardata
    Decryption (``pyaescbc.decrypt``).

This package depends only on ``_common``, never on another mode.
"""

__all__: list[str] = []
