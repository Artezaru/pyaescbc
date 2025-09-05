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

from .decrypt_AES_CBC import decrypt_AES_CBC
from .derive_key import derive_key
from .encrypt_AES_CBC import encrypt_AES_CBC

from .cleardata_to_encrypted_bundle import cleardata_to_encrypted_bundle
encrypt = cleardata_to_encrypted_bundle
from .encrypted_bundle_to_cleardata import encrypted_bundle_to_cleardata
decrypt = encrypted_bundle_to_cleardata

from .create_encrypted_bundle import create_encrypted_bundle
from .extract_cryptography_components import extract_cryptography_components

from .generate_random_iterations import generate_random_iterations
from .generate_pin_iterations import generate_pin_iterations

from .random_bytearray import random_bytearray
from .random_iv import random_iv
from .random_salt import random_salt

from .create_hmac import create_hmac
from .check_hmac import check_hmac
from .auth_error import AuthError

from .delete_bytearray import delete_bytearray

__all__ = [
    "__version__",
    "decrypt_AES_CBC",
    "derive_key",
    "encrypt_AES_CBC",
    "cleardata_to_encrypted_bundle",
    "encrypt",
    "encrypted_bundle_to_cleardata",
    "decrypt",
    "create_encrypted_bundle",
    "extract_cryptography_components",
    "generate_random_iterations",
    "generate_pin_iterations",
    "random_bytearray",
    "random_iv",
    "random_salt",
    "create_hmac",
    "check_hmac",
    "AuthError",
    "delete_bytearray",
]


