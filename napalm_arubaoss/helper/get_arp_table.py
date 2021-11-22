"""Backups and commit the configuration, and handles commit confirm."""

from napalm.base.helpers import textfsm_extractor
import logging

from napalm_arubaoss.helper.utils import mac_reformat

logger = logging.getLogger("arubaoss.helper.get_arp_table")


def get_arp_table(self, vrf):
    """
    Get device's ARP table.

    :param self: object from class
    :param vrf: not supported
    :return:
    """
    if vrf:
        msg = "VRF support has not been added " \
              "for this getter on this platform."
        raise NotImplementedError(msg)

    raw_arp = self.connection.run_cmd("show arp")
    arp_table = textfsm_extractor(self, "show_arp", raw_arp)
    for arp in arp_table:
        arp["interface"] = arp.pop("port")
        arp["mac"] = mac_reformat(arp["mac"])
        arp["age"] = -1.00  # needs to be a float - -1.00 to signal "N/A"
        arp.pop("type")  # pop because it is not present in the napalm model

    return arp_table
