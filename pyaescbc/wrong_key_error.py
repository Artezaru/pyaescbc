from typing import Optional

class WrongKeyError(Exception):
    """
    Exception raised for errors in the input key.
    """
    def __init__(self, message: str = "Incorrect key provided.", code: Optional[int] = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self):
        if self.code is not None:
            return f"{self.code}: {self.message}"
        return self.message