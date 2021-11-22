"""Get a list of LLDP neighbors."""

import logging

logger = logging.getLogger("arubaoss.helper.get_lldp_neighbors")


def get_lldp_neighbors(self):
    """
    Get a list of LLDP neighbors.

    :param self: object from class
    :return:
    """
    url = self.connection.config["api_url"] + "lldp/remote-device"
    resp = self.connection.get(url)
    logger.debug("API returned {}".format(resp.status_code))

    if resp.ok:
        neighbor_table = {}
        for neighbor in resp.json()["lldp_remote_device_element"]:
            port = neighbor["local_port"]
            if not neighbor_table.get(port):
                neighbor_table[port] = []
            remote_device = {
                "hostname": neighbor.get("system_name"),
                "port": neighbor.get("port_id"),
            }
            neighbor_table[port].append(remote_device)

        return neighbor_table
