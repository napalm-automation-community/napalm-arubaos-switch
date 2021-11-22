"""Get route to destination."""

from napalm.base.helpers import textfsm_extractor
from netaddr import IPNetwork
import logging


logger = logging.getLogger("arubaoss.helper.get_route_to")


def get_route_to(self, destination="", protocol=""):
    """
    Get route to destination.

    :param self: object from class
    :param destination:
    :param protocol:
    :return:
    """
    inner_dictionary = {
        "protocol": "",
        "current_active": True,
        "last_active": True,
        "age": -1,
        "next_hop": "",
        "outgoing_interface": "",
        "selected_next_hop": True,
        "preference": -1,
        "inactive_reason": "",
        "routing_table": "",
        "protocol_attributes": {}
    }

    bgp_dictionary = {
        "local_as": -1,
        "remote_as": -1,
        "peer_id": "",
        "as_path": "",
        "communities": -1,
        "local_preference": -1,
        "preference2": -1,
        "metric": -1,
        "metric2": -1
    }

    isis_dictionary = {
        "level": -1
    }

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
        ret = self.connection.run_cmd(cmd_dict["command"])

        route_table = textfsm_extractor(self, cmd_dict["template"], ret)
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

        ret = self.connection.cli([cmd["command"] for cmd in cmds])

        route_table = []
        for cmd in cmds:
            route_table.extend(
                textfsm_extractor(self, cmd["template"], ret[cmd["command"]])
            )

    out = {}
    for route in route_table:
        if not out.get(route["destination"]):
            out[route["destination"]] = []

        new_path = inner_dictionary.copy()
        new_path["protocol"] = route["type"]
        new_path["preference"] = int(route["distance"])
        new_path["next_hop"] = route["gateway"]

        # doesn't exist, but will be handled to be compliant with the tests
        if route["type"] == "bgp":
            new_path["protocol_attributes"] = bgp_dictionary.copy()

        # doesn't exist, but will be handled to be compliant with the tests
        if route["type"] == "isis":
            new_path["protocol_attributes"] = isis_dictionary.copy()

        out[route["destination"]].append(new_path)
    return out
