import logging

from napalm_arubaoss.helper.base import Connection

logger = logging.getLogger('arubaoss.helper.get_lldp_neighbors')

connection = Connection()


def get_lldp_neighbors():
    """Get a list of LLDP neighbors."""
    url = connection.config['api_url'] + '/lldp/remote-device'
    resp = connection.get(url)
    logger.debug("API returned {}".format(resp.status_code))

    if resp.ok:
        neighbor_table = {}
        for neighbor in resp.json()['lldp_remote_device_element']:
            port = neighbor['local_port']
            if not neighbor_table.get(port):
                neighbor_table[port] = []
            remote_device = {
                'hostname': neighbor.get('system_name'),
                'port': neighbor.get('port_id')
            }
            neighbor_table[port].append(remote_device)

        return neighbor_table
