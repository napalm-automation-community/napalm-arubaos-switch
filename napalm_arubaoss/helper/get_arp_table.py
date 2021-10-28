"""Backups and commit the configuration, and handles commit confirm."""

from napalm.base.helpers import textfsm_extractor
import logging

from napalm_arubaoss.helper.utils import mac_reformat

logger = logging.getLogger("arubaoss.helper.get_arp_table")


def get_arp_table(self, vrf):
    """Get device's ARP table."""

    if vrf:
        msg = "VRF support has not been added " \
              "for this getter on this platform."
        raise NotImplementedError(msg)

    raw_arp = self.connection.run_cmd("show arp")
    arp_table = textfsm_extractor(self, "show_arp", raw_arp)
    for arp in arp_table:
        arp["interface"] = arp.pop("port")
        arp["mac"] = mac_reformat(arp["mac"])
        arp["age"] = "N/A"

    return arp_table
