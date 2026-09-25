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

from .__version__ import __version__

# High-level API (recommended)
from .cleardata_to_encrypted_bundle import cleardata_to_encrypted_bundle, DEFAULT_ITERATIONS
encrypt = cleardata_to_encrypted_bundle
from .encrypted_bundle_to_cleardata import encrypted_bundle_to_cleardata
decrypt = encrypted_bundle_to_cleardata
from .auth_error import AuthError

# Building blocks (advanced usage)
from .derive_key import derive_key, MIN_ITERATIONS, MAX_ITERATIONS
from .create_hmac import create_hmac
from .check_hmac import check_hmac
from .create_encrypted_bundle import create_bundle_header, create_encrypted_bundle
from .extract_cryptography_components import extract_cryptography_components, BundleComponents

# Utilities
from .random_bytearray import random_bytearray
from .random_iv import random_iv
from .random_salt import random_salt
from .delete_bytearray import delete_bytearray

# NOTE: encrypt_AES_CBC and decrypt_AES_CBC are internal and intentionally not exported:
# decrypting unauthenticated data exposes a padding oracle. Use encrypt / decrypt instead.

__all__ = [
    "__version__",
    # High-level API
    "encrypt",
    "decrypt",
    "cleardata_to_encrypted_bundle",
    "encrypted_bundle_to_cleardata",
    "AuthError",
    "DEFAULT_ITERATIONS",
    # Building blocks
    "derive_key",
    "MIN_ITERATIONS",
    "MAX_ITERATIONS",
    "create_hmac",
    "check_hmac",
    "create_bundle_header",
    "create_encrypted_bundle",
    "extract_cryptography_components",
    "BundleComponents",
    # Utilities
    "random_bytearray",
    "random_iv",
    "random_salt",
    "delete_bytearray",
]