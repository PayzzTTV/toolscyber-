"""Custom exceptions for RootGuard."""


class HashError(Exception):
    """Raised when a file cannot be hashed."""

    def __init__(self, path: str, original: Exception) -> None:
        self.path = path
        self.original = original
        super().__init__(f"Cannot hash '{path}': {original}")


class BaselineNotFoundError(Exception):
    """Raised when the baseline file does not exist."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Baseline not found at '{path}'. Run 'baseline' first.")
