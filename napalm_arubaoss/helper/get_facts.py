"""Get general device information."""

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

    # If it's a Stack, use `/system/status/global_info`
    if call.status_code == 404:
        system_status_url = connection.config['api_url'] +\
            'system/status/global_info'
        call = connection.get(system_status_url)
    if call.ok:
        rest_out = call.json()
        out['hostname'] = rest_out['name']
        out['os_version'] = rest_out['firmware_version']
        out['serial_number'] = rest_out.get('serial_number', '')
        out['model'] = rest_out.get('product_model', '')

        # get domain name to generate the FQDN
        call = connection.get(dns_url)
        if call.ok:
            rest_out = call.json()
            # return "{{hostname}}." if no domain is configured
            out['fqdn'] = out['hostname'] + "." +\
                rest_out.get('dns_domain_names', '.')[0]

    # Get interface list
    call = connection.get(switch_status_url)
    if call.ok:
        rest_out = call.json()
        if rest_out.get('switch_type', 'ST_STANDALONE') == 'ST_STACKED':
            serial_url = connection.config['api_url'] +\
                'system/status/members/1'
            call = connection.get(serial_url)
            if call.ok:
                out['serial_number'] = call.json().get('serial_number')
                out['model'] = call.json().get('product_model')
        for blade in rest_out['blades']:
            for ports in blade['data_ports']:
                out['interface_list'].append(ports['port_name'])

    return out
