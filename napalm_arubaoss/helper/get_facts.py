import logging

from napalm_arubaoss.helper.base import Connection

logger = logging.getLogger('arubaoss.helper.get_facts')

connection = Connection()


def get_facts():
    """Get general device information."""
    system_status_url = connection.config['api_url'] + 'system/status'
    switch_status_url = connection.config['api_url'] + 'system/status/switch'
    dns_url = connection.config['api_url'] + 'dns'
    out = {
        'vendor': 'HPE Aruba',
        'interface_list': []
    }

    call = connection.get(system_status_url)
    if call.ok:
        rest_out = call.json()
        out['hostname'] = rest_out['name']
        out['os_version'] = rest_out['firmware_version']
        out['serial_number'] = rest_out['serial_number']
        out['model'] = rest_out['product_model']

        # get domain name to generate the FQDN
        call = connection.get(dns_url)
        if call.ok:
            rest_out = call.json()
            out['fqdn'] = out['hostname'] + "." + \
                          rest_out['dns_domain_names'][0]

    # Get interface list
    call = connection.get(switch_status_url)
    if call.ok:
        rest_out = call.json()
        for blade in rest_out['blades']:
            for ports in blade['data_ports']:
                out['interface_list'].append(ports['port_name'])

    return out
