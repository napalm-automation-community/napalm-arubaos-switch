"""Execute ping on the device and returns a dictionary with the result."""

from napalm_arubaoss.helper.base import Connection
import logging

logger = logging.getLogger('arubaoss.helper.ping')

connection = Connection()


def ping(destination, timeout=2):
    """
    Execute ping on the device and returns a dictionary with the result.

    :param destination: needed argument
    :param timeout: not implemented as not available from device
    :return: returns a dictionary containing the hops and probes
    """
    url = connection.config['api_url'] + 'ping'
    data = {
        'destination': {
            'ip_address': {
                'version': 'IAV_IP_V4',
                "octets": destination
            }
        },
        "timeout_in_seconds": timeout
    }
    data_post = connection.post(url, json=data)

    if not data_post.status_code == 200:
        return {'error': 'unknown host {}'.format(destination)}

    if 'PR_OK' in data_post.json().get('result'):
        result = {
            'success': {
                'probes_sent': 1,
                'packet_loss': 0,
                'rtt_min': data_post.json().get('rtt_in_milliseconds'),
                'rtt_max': data_post.json().get('rtt_in_milliseconds'),
                'rtt_avg': data_post.json().get('rtt_in_milliseconds'),
                'rtt_stddev': 0,
                'results': {
                    'ip_address': destination,
                    'rtt': data_post.json().get('rtt_in_milliseconds')
                }
            }
        }

        return result
