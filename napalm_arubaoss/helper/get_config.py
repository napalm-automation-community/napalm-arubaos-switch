"""Get configuration stored on the device."""

import logging

from napalm_arubaoss.helper.base import Connection

logger = logging.getLogger('arubaoss.helper.get_config')

connection = Connection()


def get_config(retrieve='all'):
    """Get configuration stored on the device."""
    out = {'startup': '', 'candidate': '', 'running': ''}

    cmd_mapping = {
        'display saved-configuration': 'startup',
        'show config REST_Payload_Backup': 'candidate',
        'show running-config': 'running'
    }
    cmd_mapping = {
        key: value for key, value in cmd_mapping.items() if retrieve == value
    } if not retrieve == 'all' else cmd_mapping

    outputs = connection.cli([cmd for cmd, config in cmd_mapping.items()])

    for okey, ovalue in outputs.items():
        out[cmd_mapping[okey]] = ovalue

    return out
