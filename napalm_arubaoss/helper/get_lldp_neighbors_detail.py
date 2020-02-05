"""Get LLDP neighbor information."""

import logging

from napalm_arubaoss.helper.base import Connection

logger = logging.getLogger('arubaoss.helper.get_lldp_neighbors_detail')

connection = Connection()


def get_lldp_neighbors_detail(*args, **kwargs):
    """Get LLDP neighbor information."""
    url = connection.config['api_url'] + '/lldp/remote-device'
    resp = connection.get(url)
    logger.debug('API returned {}'.format(resp.status_code))

    if resp.ok:
        neighbor_table = {}
        for neighbor in resp.json()['lldp_remote_device_element']:
            port = neighbor['local_port']
            if not neighbor_table.get(port):
                neighbor_table[port] = []
            remote_device = {
                'remote_system_name': neighbor.get('system_name'),
                'remote_chassis_id': neighbor.get('chassis_id'),
                'remote_port': neighbor.get('port_id'),
                'remote_port_description':
                    neighbor.get('port_description'),
                'remote_system_description':
                    ''.join(neighbor.get('system_description')),
                'remote_system_capab':
                    [k for k, v in neighbor.get(
                        'capabilities_supported').items() if v is True],
                'remote_system_enable_capab':
                    [k for k, v in neighbor.get(
                        'capabilities_enabled').items() if v is True]
            }
            neighbor_table[port].append(remote_device)

        return neighbor_table
