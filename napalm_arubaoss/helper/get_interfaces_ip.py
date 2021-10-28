"""Get IP interface IP addresses."""

from netaddr import IPNetwork
import logging

logger = logging.getLogger("arubaoss.helper.get_interfaces_ip")


def get_interfaces_ip(connection):
    """Get IP interface IP addresses."""
    "Looks like there's a bug n ArubaOS and is not returning IPv6"

    url = connection.config["api_url"] + "ipaddresses"
    output = {}
    resp = connection.get(url)
    if resp.status_code == 200:
        for address in resp.json().get("ip_address_subnet_element"):
            iface_name = "VLAN" + str(address["vlan_id"])
            if iface_name not in output.keys():
                output[iface_name] = {}
            ip = IPNetwork(
                "{}/{}".format(
                    address["ip_address"]["octets"], address["ip_mask"]["octets"]
                )
            )
            version = "ipv" + str(ip.version)
            if version not in output[iface_name].keys():
                output[iface_name][version] = {}
            output[iface_name][version][str(ip.ip)] = {"prefix_length": ip.prefixlen}

    return output
