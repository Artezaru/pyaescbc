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

from typing import Optional

class AuthError(Exception):
    """
    Exception raised for errors related to the decryption key in ``pyaescbc``.

    This exception is typically raised when the provided password or key
    is incorrect.

    The display message will be shown in the following format if a code is provided:

    .. code-block:: console

        AuthError: [<code>] <message>

    Parameters
    ----------
    message : str, optional
        The error message to be displayed. Default is ""
    code : Optional[int], optional
        An optional error code associated with the exception. Default is None.

    Notes
    -----
    You can raise this exception when the HMAC verification fails
    during decryption, which usually means the wrong key was used (if the data were not 
    """
    def __init__(self, message: str = "", code: Optional[int] = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self):
        if self.code is not None:
            return f"[{self.code}] {self.message}"
        return self.message
