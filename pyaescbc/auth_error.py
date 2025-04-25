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
