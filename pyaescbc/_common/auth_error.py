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
Exception raised when the authentication of a bundle fails.
"""

from typing import Optional


class AuthError(Exception):
    r"""
    Raised when the HMAC of a bundle does not match, i.e. when:

    - the password (``decrypt``) or the key (``decrypt_with_key``) is wrong;
    - the ``authdata`` differs from the one given at encryption;
    - or the bundle has been tampered with.

    These cases are deliberately indistinguishable. A malformed bundle (wrong size,
    unknown magic or version) raises a ``ValueError`` instead, before any key derivation.

    The message is displayed as follows when a code is given:

    .. code-block:: console

        AuthError: [<code>] <message>

    .. code-block:: python

        import pyaescbc

        try:
            cleardata = pyaescbc.decrypt(encrypted_bundle, password)
        except pyaescbc.AuthError:
            print("Wrong password.")

    Parameters
    ----------
    message : str, optional
        The error message. Default is ``""``.

    code : Optional[int], optional
        An optional error code. Default is ``None``.

    Attributes
    ----------
    message : str
        The error message.

    code : Optional[int]
        The error code, or ``None``.
    """

    def __init__(self, message: str = "", code: Optional[int] = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        if self.code is not None:
            return f"[{self.code}] {self.message}"
        return self.message
