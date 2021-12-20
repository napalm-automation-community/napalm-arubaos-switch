"""Get NTP servers."""

import logging

logger = logging.getLogger("arubaoss.helper.get_ntp_servers")


def get_ntp_servers(self):
    """
    Get NTP servers.

    # TODO: add IPv6 support, currently getting 404 from the API

    :param self: object from class
    :return:
    """
    base_url = self.connection.config["api_url"]
    ipv4_url = f"{base_url}config/ntp/server/ip4addr"
    name_url = f"{base_url}config/ntp/server-name/ASCII-STR"

    ipv4_resp = self.connection.get(ipv4_url)
    name_resp = self.connection.get(name_url)

    output = {}

    if ipv4_resp.status_code == 200:
        for server in ipv4_resp.json().get("ntpServerIp4addr_element"):
            output[server["ip4addr"]["ip4addr_value"]] = {}

    if name_resp.status_code == 200:
        for server in name_resp.json().get("ntpServerNameASCIISTR_element"):
            output[server["ASCII-STR"]["ASCII-STR_value"]] = {}

        return output
