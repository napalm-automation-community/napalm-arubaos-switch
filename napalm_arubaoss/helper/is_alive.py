"""Check if device connection is alive."""

from napalm.base.exceptions import ConnectionClosedException
import logging

logger = logging.getLogger("arubaoss.helper.is_alive")


def is_alive(self):
    """Check if device connection is alive."""
    """check if session cookie is still valid
    Returns:
        True - Session cookie is still valid
        None - There's an error
    """
    url = self.connection.config["api_url"] + "system"
    endpoint = self.connection.get(url)
    if endpoint.status_code == 200:
        "Session cookie is still valid"
        return {"is_alive": True}
    else:
        raise ConnectionClosedException("HTTP session is closed")
