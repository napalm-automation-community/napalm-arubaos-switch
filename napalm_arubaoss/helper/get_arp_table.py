"""Backups and commit the configuration, and handles commit confirm."""

from napalm.base.helpers import textfsm_extractor
import logging

from napalm_arubaoss.helper.base import Connection
from napalm_arubaoss.helper.utils import mac_reformat

logger = logging.getLogger('arubaoss.helper.get_arp_table')

connection = Connection()


def get_arp_table(self_obj=None, *args, **kwargs):
    """Get device's ARP table."""
    if not self_obj:
        return []
    raw_arp = connection.run_cmd("show arp")
    arp_table = textfsm_extractor(self_obj, "show_arp", raw_arp)
    for arp in arp_table:
        arp['interface'] = arp.pop('port')
        arp['mac'] = mac_reformat(arp['mac'])
        arp['age'] = 'N/A'

    return arp_table
