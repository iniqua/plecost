class PlecostError(Exception):
    """Base exception for Plecost."""


class NotWordPressError(PlecostError):
    """Target is not a WordPress site."""


class DatabaseNotFoundError(PlecostError):
    """CVE database not found. Run: plecost update-db"""


class HTTPError(PlecostError):
    """HTTP request failed."""
