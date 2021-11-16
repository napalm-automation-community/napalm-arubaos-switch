"""Get the mac-address table of the device."""

import logging

from napalm_arubaoss.helper.utils import mac_reformat

logger = logging.getLogger("arubaoss.helper.get_mac_address_table")


def get_mac_address_table(self):
    """
    Get the mac-address table of the device.

    :param self: object from class
    :return:
    """
    url = self.connection.config["api_url"] + "mac-table"
    resp = self.connection.get(url)
    if resp.status_code == 200:
        table = []
        for entry in resp.json().get("mac_table_entry_element"):
            item = {
                "mac": mac_reformat(entry["mac_address"]),
                "interface": entry["port_id"],
                "vlan": entry["vlan_id"],
                "active": True,
                "static": False,  # not supported
                "moves": 0,  # not supported
                "last_move": 0.0  # not supported
            }
            table.append(item)

        return table
