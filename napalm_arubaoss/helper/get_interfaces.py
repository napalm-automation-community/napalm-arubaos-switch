"""Get the interfaces of the device."""

import logging

logger = logging.getLogger("arubaoss.helper.get_interfaces")


def get_interfaces(self):
    """Get IP interface IP addresses."""
    url_ports = self.connection.config["api_url"] + "ports"
    url_port_stats = self.connection.config["api_url"] + "port-statistics"

    interface_template = {
        'is_up': False,
        'is_enabled': False,
        'description': '',
        'last_flapped': -1.0,
        'speed': 1000,
        'mtu': -1,
        'mac_address': 'FA:16:3E:57:33:61',
    }
    output = {}

    resp_ports = self.connection.get(url_ports)
    resp_port_stats = self.connection.get(url_port_stats)

    if not resp_ports.status_code == 200:
        logger.error("didn't get status code 200 from %s", url_ports)
        return output

    if not resp_port_stats.status_code == 200:
        logger.error("didn't get status code 200 from %s", url_port_stats)
        return output

    resp_ports_json = resp_ports.json()
    for interface in resp_ports_json.get("port_element", []):
        # show interfaces 1 | include MAC[[:space:]]Address
        i_id = interface.get("id")
        description = interface.get("name")
        is_up = interface.get("is_port_up")
        is_enabled = interface.get("is_port_enabled")

        if i_id not in output.keys():
            output[i_id] = interface_template.copy()

        output[i_id]["description"] = description
        output[i_id]["is_up"] = is_up
        output[i_id]["is_enabled"] = is_enabled

    resp_port_stats_json = resp_port_stats.json()
    for interface_stats in resp_port_stats_json.get("port_statistics_element", []):
        i_id = interface_stats.get("id")
        speed = interface_stats.get("port_speed_mbps")

        if i_id not in output.keys():
            output[i_id] = interface_template.copy()

        output[i_id]["speed"] = speed

    for interface_id, interface_values in output.items():
        resp = self.connection.run_cmd(
            f"show interfaces {interface_id} | include MAC[[:space:]]Address"
        )

        resp = resp.replace(" ", "")
        resp = resp.split(":")
        mac_raw = resp[1]
        mac_raw = mac_raw.replace("-", "")
        mac = ':'.join(mac_raw[i:i+2] for i in range(0, 12, 2))
        mac = mac.upper()

        output[interface_id]["mac_address"] = mac

    return output
