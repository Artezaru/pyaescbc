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
pyaescbc: AES-256-CBC + HMAC-SHA256 encryption (Encrypt-then-MAC) of ``bytearray`` data.

Public API
----------
Password mode (``PACB`` bundles, slow PBKDF2 key derivation on every call):

- :func:`encrypt` / :func:`decrypt`
- :data:`DEFAULT_ITERATIONS`, :data:`MIN_ITERATIONS`, :data:`MAX_ITERATIONS`

Key mode (``PACK`` bundles, random 32-byte key, no key derivation):

- :func:`encrypt_with_key` / :func:`decrypt_with_key`
- :func:`generate_key`, :data:`KEY_SIZE`

Both modes:

- :class:`AuthError`, raised when the password/key or the authdata is wrong,
  or the data has been tampered with
- :func:`delete_bytearray`, to wipe secrets from memory (best-effort)

Only the names listed in ``__all__`` are public. Everything in the ``_common``,
``_password_mode`` and ``_key_mode`` sub-packages is internal and may change in any release.
"""

from .__version__ import __version__

# Password mode
from ._password_mode.cleardata_to_encrypted_bundle import cleardata_to_encrypted_bundle as encrypt, DEFAULT_ITERATIONS
from ._password_mode.encrypted_bundle_to_cleardata import encrypted_bundle_to_cleardata as decrypt
from ._password_mode.derive_key import MIN_ITERATIONS, MAX_ITERATIONS

# Key mode
from ._key_mode.cleardata_to_key_bundle import cleardata_to_key_bundle as encrypt_with_key
from ._key_mode.key_bundle_to_cleardata import key_bundle_to_cleardata as decrypt_with_key
from ._key_mode.expand_key import generate_key, KEY_SIZE

# Both modes
from ._common.auth_error import AuthError
from ._common.delete_bytearray import delete_bytearray

__all__ = [
    "__version__",
    # Password mode
    "encrypt",
    "decrypt",
    "DEFAULT_ITERATIONS",
    "MIN_ITERATIONS",
    "MAX_ITERATIONS",
    # Key mode
    "encrypt_with_key",
    "decrypt_with_key",
    "generate_key",
    "KEY_SIZE",
    # Both modes
    "AuthError",
    "delete_bytearray",
]


# ---------------------------------------------------------------------------
# Deprecated names (public in pyaescbc 2.1, internal since 2.2).
# They still work but emit a DeprecationWarning.
# To release 3.0: delete everything from here to the end of the file.
# ---------------------------------------------------------------------------
import importlib as _importlib
import warnings as _warnings

_DEPRECATED = {
    # old public name                 (internal module,                                   attribute)
    "cleardata_to_encrypted_bundle":   ("._password_mode.cleardata_to_encrypted_bundle",  "cleardata_to_encrypted_bundle"),
    "encrypted_bundle_to_cleardata":   ("._password_mode.encrypted_bundle_to_cleardata",  "encrypted_bundle_to_cleardata"),
    "derive_key":                      ("._password_mode.derive_key",                     "derive_key"),
    "create_bundle_header":            ("._password_mode.create_encrypted_bundle",        "create_bundle_header"),
    "create_encrypted_bundle":         ("._password_mode.create_encrypted_bundle",        "create_encrypted_bundle"),
    "extract_cryptography_components": ("._password_mode.extract_cryptography_components", "extract_cryptography_components"),
    "BundleComponents":                ("._password_mode.extract_cryptography_components", "BundleComponents"),
    "create_hmac":                     ("._common.mac",                                   "create_hmac"),
    "check_hmac":                      ("._common.mac",                                   "check_hmac"),
    "random_bytearray":                ("._common.random",                                "random_bytearray"),
    "random_iv":                       ("._common.random",                                "random_iv"),
    "random_salt":                     ("._common.random",                                "random_salt"),
}


def __getattr__(name: str):
    # Only called for names that are not defined above (PEP 562)
    if name in _DEPRECATED:
        module, attribute = _DEPRECATED[name]
        _warnings.warn(
            f"pyaescbc.{name} is internal since pyaescbc 2.2 and will be removed in 3.0. "
            f"Use the public API instead: {', '.join(n for n in __all__ if n != '__version__')}.",
            DeprecationWarning,
            stacklevel=2,
        )
        return getattr(_importlib.import_module(module, __name__), attribute)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(__all__)
