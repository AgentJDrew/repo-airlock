"""A perfectly ordinary, clean file with nothing to flag."""


def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b


def greet(name: str) -> str:
    return f"Hello, {name}!"


class Config:
    """Application configuration with only placeholder-style values."""

    api_key = "your-api-key-here"
    debug = False
