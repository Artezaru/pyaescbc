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
Internal building blocks shared by every bundle format of ``pyaescbc``.

**Internal: no stability guarantee.** Nothing in this package is part of the public
API and it may change in any release. Use the names exported by ``pyaescbc``
(``encrypt``, ``decrypt``, ``encrypt_with_key``, ``decrypt_with_key``, ...).

This package never depends on a specific format (``_password_mode``, ``_key_mode``):
the formats depend on it, never the other way around.

Modules
-------
aes_cbc
    Raw AES-256-CBC encryption / decryption with PKCS7 padding (unauthenticated).
mac
    HMAC-SHA256 tag creation and constant-time comparison.
etm
    Encrypt-then-MAC and verify-then-decrypt: the only correct way to chain the above.
kdf
    HKDF expansion of a 32-byte secret into an AES key and an HMAC key.
bundle
    Generic ``header | hmac | cipherdata`` layout: assembly and splitting.
formats
    Magic numbers, sizes and bundle identification.
random
    CSPRNG helpers (IV, salt, keys).
delete_bytearray
    Best-effort wiping of secrets in memory.
auth_error
    The exception raised when authentication fails.
"""

__all__: list[str] = []
