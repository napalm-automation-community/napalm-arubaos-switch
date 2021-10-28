"""Get NTP servers."""

import logging

logger = logging.getLogger("arubaoss.helper.get_ntp_servers")


def get_ntp_servers(self):
    """Get NTP servers."""
    " TO-DO: add IPv6 support, currently getting 404 from the API"
    url = self.connection.config["api_url"] + "config/ntp/server/ip4addr"
    resp = self.connection.get(url)
    if resp.status_code == 200:
        output = {}
        for server in resp.json().get("ntpServerIp4addr_element"):
            output[server["ip4addr"]["ip4addr_value"]] = {}
        return output
