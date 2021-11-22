"""Get IP interface IP addresses."""

from netaddr import IPNetwork
import logging

logger = logging.getLogger("arubaoss.helper.get_interfaces_ip")


def get_interfaces_ip(self):
    """
    Get IP interface IP addresses.

    !!! Looks like there's a bug n ArubaOS and is not returning IPv6

    :param self: object from class
    :return:
    """
    url = self.connection.config["api_url"] + "ipaddresses"
    output = {}
    resp = self.connection.get(url)
    if resp.status_code == 200:
        for address in resp.json().get("ip_address_subnet_element", []):
            vlan_id = address.get("vlan_id", "")
            iface_name = "VLAN{vlan_id}".format(vlan_id=str(vlan_id))

            if iface_name not in output.keys():
                output[iface_name] = {}

            ip_address = address.get("ip_address", {}).get("octets")
            ip_mask = address.get("ip_mask", {}).get("octets")

            if ip_address and ip_mask:
                ip = IPNetwork(
                    "{ip_address}/{ip_mask}".format(
                        ip_address=ip_address,
                        ip_mask=ip_mask
                    )
                )

                version = "ipv{ip_version}".format(ip_version=str(ip.version))

                if version not in output[iface_name].keys():
                    output[iface_name][version] = {}
                output[iface_name][version][str(ip.ip)] = {
                    "prefix_length": ip.prefixlen
                }

    return output
