"""Get route to destination."""

from napalm.base.helpers import textfsm_extractor
from netaddr import IPNetwork
import logging

from napalm_arubaoss.helper.base import Connection

logger = logging.getLogger("arubaoss.helper.get_route_to")


def get_route_to(connection, destination="", protocol="", self_obj=None):
    """
    Get route to destination.

    :param destination:
    :param protocol:
    :return:
    """
    if not self_obj:
        return {}
    if destination:
        ip_address = IPNetwork(destination)

        cmds = {
            4: {
                "template": "show_ip_route",
                "command": "show ip route {} {}".format(ip_address.ip, protocol),
            },
            6: {
                "template": "show_ipv6_route",
                "command": "show ipv6 route {} {}".format(ip_address.ip, protocol),
            },
        }
        cmd_dict = cmds[ip_address.version]
        ret = connection.run_cmd(cmd_dict["command"])

        route_table = textfsm_extractor(self_obj, cmd_dict["template"], ret)
    else:
        cmds = [
            {
                "template": "show_ip_route",
                "command": "show ip route {} {}".format(destination, protocol),
            },
            {
                "template": "show_ipv6_route",
                "command": "show ipv6 route {} {}".format(destination, protocol),
            },
        ]

        ret = connection.cli([cmd["command"] for cmd in cmds])

        route_table = []
        for cmd in cmds:
            route_table.extend(
                textfsm_extractor(self_obj, cmd["template"], ret[cmd["command"]])
            )

    out = {}
    for route in route_table:
        if not out.get(route["destination"]):
            out[route["destination"]] = []
        new_path = {
            "protocol": route["type"],
            "preference": int(route["distance"]),
            "next_hop": route["gateway"],
        }
        out[route["destination"]].append(new_path)
    return out
