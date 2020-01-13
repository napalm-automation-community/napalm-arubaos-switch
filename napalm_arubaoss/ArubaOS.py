"""ArubaOS-Switch Napalm driver."""
import base64
from itertools import zip_longest
from json import JSONDecodeError
from time import sleep

from requests.models import Response
from requests_futures.sessions import FuturesSession
from concurrent.futures import as_completed
import logging
import socket
from netaddr import IPNetwork

from napalm.base.helpers import textfsm_extractor
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectAuthError,
    ConnectionClosedException,
    CommandErrorException,
    CommandTimeoutException,
    MergeConfigException,
    ReplaceConfigException
)

""" Debugging
import http.client
http.client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
"""

log = logging.getLogger(__name__)

# disable anoying warning
# requests.packages.urllib3.disable_warnings()


class ArubaOSS(NetworkDriver):
    """Class for connecting to aruba-os devices using the rest-api."""

    def __init__(
            self,
            hostname,
            username='',
            password='',
            timeout=10,
            optional_args={}
    ):
        """Instantiate the module."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        # ----------------------------------------------------------------------------------------
        # optional arguments
        # ----------------------------------------------------------------------------------------

        self.api = optional_args.get("api", "v6")
        self.proto = 'https' if optional_args.get("ssl", True) else 'http'

        self._api_url = '{}://{}/rest/{}/'.format(
            self.proto,
            self.hostname,
            self.api
        )

        self._apisession = FuturesSession()
        self._apisession.verify = optional_args.get("ssl_verify", True)
        self._apisession.headers = {'Content-Type': 'application/json'}
        # bug #4 - random delay while re-using TCP connection - workaround:
        self._apisession.keep_alive = optional_args.get("keepalive", False)
        self._login_url = self._api_url + "login-sessions"
        self._cli_url = self._api_url + 'cli'
        self._system_status_url = self._api_url + 'system/status'
        self._ipaddresses_url = self._api_url + 'ipaddresses'

        self.cli_output = {}

    def get(self, *args, **kwargs) -> Response:
        """
        Call a single command (Helper-Function).

        :param args:
        :param kwargs:
        :return:
        """
        ret = self._apisession.get(*args, **kwargs)

        return ret.result()

    def post(self, *args, **kwargs) -> Response:
        """
        Call a single command (Helper-Function).

        :param args:
        :param kwargs:
        :return:
        """
        ret = self._apisession.post(*args, **kwargs)

        return ret.result()

    def put(self, *args, **kwargs) -> Response:
        """
        Call a single command (Helper-Function).

        :param args:
        :param kwargs:
        :return:
        """
        ret = self._apisession.put(*args, **kwargs)

        return ret.result()

    def delete(self, *args, **kwargs) -> Response:
        """
        Call a single command (Helper-Function).

        :param args:
        :param kwargs:
        :return:
        """
        ret = self._apisession.delete(*args, **kwargs)

        return ret.result()

    def open(self):
        """Open connection to the network device."""
        params = {'userName': self.username, 'password': self.password}

        rest_login = self.post(
            self._login_url,
            json=params,
            timeout=self.timeout
        )

        if not rest_login.status_code == 201:
            raise ConnectAuthError("Login failed")

        session = rest_login.json()
        self._apisession.headers['cookie'] = session['cookie']

        return True

    def is_alive(self):
        """Check if device connection is alive."""
        """check if session cookie is still valid
        Returns:
            True - Session cookie is still valid
            None - There's an error
        """
        url = self._api_url + 'system'
        endpoint = self.get(url)
        if endpoint.status_code == 200:
            "Session cookie is still valid"
            return {"is_alive": True}
        else:
            raise ConnectionClosedException("HTTP session is closed")

    @staticmethod
    def _read_candidate(candidate):
        with open(candidate) as candidate_config:
            return ''.join(candidate_config.readlines())

    def _transaction_status(self, url):
        status = 'CRS_IN_PROGRESS'
        elapsed = 0
        while status == 'CRS_IN_PROGRESS' and elapsed < self.timeout:
            call = self.get(url)
            if call.status_code in range(200, 300):
                status = call.json()
                return status
            elapsed += 1
            sleep(1)
        if elapsed == (int(self.timeout) - 1) and status == 'CRS_IN_PROGRESS':
            raise CommandTimeoutException("Transaction timed out")

    @staticmethod
    def _str_to_b64(spayload):
        """Convert from str to b64 for aoss API."""
        payload_b64 = base64.b64encode(spayload.encode())

        return payload_b64.decode('utf-8')

    @staticmethod
    def _mac_reformat(mac):
        t = iter(mac.replace("-", ""))

        return ':'.join(a+b for a, b in zip_longest(t, t, fillvalue=""))

    def load_replace_candidate(self, filename=None, config=None):
        """Replace running config with the candidate."""
        """ Implentation of napalm module load_replace_candidate()
        ArubaOS-Switch supports payload_type options:
            - "RPT_PATCH_FILE" -> not implemented
            - "RPT_BACKUP_FILE" -> Implemented

        Note: the maximum content_length = 16072,
        "HTTP/1.1 413 Request Entity Too Large" is returned above that!!!
        """
        url = self._api_url + 'system/config/payload'
        payload = {"payload_type": "RPT_BACKUP_FILE"}
        if filename is not None:
            config = self._read_candidate(filename)

        if config is not None:
            payload['config_base64_encoded'] = ArubaOSS._str_to_b64(config)
            load = self.post(url, json=payload)
            if load.status_code != 200:
                raise ReplaceConfigException("Load configuration failed")

    def load_merge_candidate(self, filename=None, config=None):
        """Merge candidate configuration with the running one."""
        """
        Imperative config change:
         Merge new config with existing one. There's no config validation
         nor atomic commit!. Only configuration commands are supported,
         "configure terminal" is not required. Use with caution.

        """
        if filename is not None:
            config = self._read_candidate(filename)

        if config is not None:
            if isinstance(config, str):
                config = config.split('\n')
            if not self._config_batch(cmd_list=config):
                raise MergeConfigException("Configuration merge failed")

        # mimic load_replace_candidate behaviour, by making sure candidate
        # config exactly matches our merged configuration
        self._backup_config(destination='REST_Payload_Backup')

    def cli(self, commands):
        """Run CLI commands through the REST API."""
        self.cli_output = {}
        if not isinstance(commands, list):
            self.cli_output['error'] = 'Provide a list of commands'
            return self.cli_output

        async_calls = (
            self._apisession.post(
                url=self._cli_url,
                json={'cmd': command},
                hooks={
                    'response': self._callback(
                        output=self.cli_output,
                        command=command
                    )
                }
            ) for command in commands
        )

        [call.result() for call in as_completed(async_calls)]

        return self.cli_output

    def _callback(self, *args, **kwargs):
        """
        Return Callback for async calls.

        ArubaOSS.cli uses it.

        :param args:
        :param kwargs:
        :return: callback function
        """
        def callback(call, *cargs, **ckwargs):
            self.cli_output = kwargs.get('output')
            passed_cmd = kwargs.get('command')
            try:
                json_ret = call.json()
            except JSONDecodeError:
                json_ret = {}

            cmd = json_ret.get('cmd')
            result_base64 = json_ret.get('result_base64_encoded', '')

            if not cmd == passed_cmd:
                self.cli_output[passed_cmd] = 'cmd not found in output'
                return

            if not result_base64:
                self.cli_output[passed_cmd] = 'no result found in output'
                return

            result = base64.b64decode(result_base64).decode('utf-8')
            self.cli_output[passed_cmd] = result

        return callback

    def _run_cmd(self, cmd):
        ret = self.cli([cmd])
        return ret[cmd]

    def get_arp_table(self, *args, **kwargs):
        """Get device's ARP table."""
        raw_arp = self._run_cmd("show arp")
        arp_table = textfsm_extractor(self, "show_arp", raw_arp)
        for arp in arp_table:
            arp['interface'] = arp.pop('port')
            arp['mac'] = self._mac_reformat(arp['mac'])
            arp['age'] = 'N/A'

        return arp_table

    def get_environment(self):
        """Get environment readings."""
        """
        Currently (API v7) the API does not support reading information about
        fans, temperature, power or CPU.
        A textfsm template needs to be created to parse:
         - show system temperature
         - show system fan
         - show system power-consumption
         - show system power-supply
         - show system information (CPU/MEM)
        """
        output = {
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {},
            "memory": {}
        }

        return output

    def get_config(self, retrieve='all', full=False):
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

        outputs = self.cli([cmd for cmd, config in cmd_mapping.items()])

        for okey, ovalue in outputs.items():
            out[cmd_mapping[okey]] = ovalue

        return out

    def get_facts(self):
        """Get general device information."""
        out = {
            'vendor': 'HPE Aruba',
            'interface_list': []
        }

        call = self.get(self._system_status_url)
        if call.ok:
            rest_out = call.json()
            out['hostname'] = rest_out['name']
            out['os_version'] = rest_out['firmware_version']
            out['serial_number'] = rest_out['serial_number']
            out['model'] = rest_out['product_model']

            # get domain name to generate the FQDN
            url = self._api_url + 'dns'
            call = self.get(url)
            if call.ok:
                rest_out = call.json()
                out['fqdn'] = out['hostname'] + "." + \
                    rest_out['dns_domain_names'][0]

        # Get interface list
        url = self._api_url + 'system/status/switch'
        call = self.get(url)
        if call.ok:
            rest_out = call.json()
            for blade in rest_out['blades']:
                for ports in blade['data_ports']:
                    out['interface_list'].append(ports['port_name'])

        return out

    def discard_config(self):
        """Discard the candidate configuration."""
        self._backup_config(destination='REST_Payload_Backup')

    def compare_config(self):
        """Compare the running config with the candidate one."""
        url = self._api_url + 'system/config/cfg_restore/latest_diff'
        check_url = url + '/status'
        data = {
                "server_type": "ST_FLASH",
                "file_name": "REST_Payload_Backup",
                "is_oobm": False
                }
        # trigger configuration comparison
        diff = self.post(url, json=data)

        if not diff.ok:
            raise CommandErrorException("diff generation failed, raise status")

        diff_output = self.get(check_url)

        if not diff_output.status_code == 200:
            raise CommandErrorException("diff generation failed, raise status")

        if not diff_output.json()['diff_add_list'] and \
                not diff_output.json()['diff_remove_list']:
            # return empty string to signal the candidate
            # and running configs are the same

            return ''
        else:
            return diff_output.json()

    def commit_config(self, message=None, confirm=0):
        """Backups and commit the configuration, and handles commit confirm."""
        self._backup_config()
        log.debug('Confirm rollback time is {}'.format(str(confirm)))
        if confirm > 0:
            candidate = self.get_config(retrieve='candidate')['candidate'][:-2]
            candidate_confirm = candidate + 'job ROLLBACK delay {} \
                "cfg-restore flash backup_running"\n'.format(str(confirm))
            self.load_replace_candidate(config=candidate_confirm)
        self._commit_candidate(config='REST_Payload_Backup')

    def _commit_candidate(self, config):
        """Commit the candidate configuration."""
        url = self._api_url + 'system/config/cfg_restore'
        data = {
                "server_type": "ST_FLASH",
                "file_name": config,
                "is_oobm": False
                }
        cmd_post = self.post(url, json=data)

        if not cmd_post.json()['failure_reason']:
            check_url = url + '/status'

            return self._transaction_status(check_url)

    def get_mac_address_table(self):
        """Get the mac-address table of the device."""
        url = self._api_url + 'mac-table'
        resp = self.get(url)
        if resp.status_code == 200:
            table = []
            for entry in resp.json().get('mac_table_entry_element'):
                item = {
                    'mac': self._mac_reformat(entry['mac_address']),
                    'interface': entry['port_id'],
                    'vlan': entry['vlan_id'],
                    'active': True,
                    # 'static': False,  # not supported
                    # 'moves': 0,  # not supported
                    # 'last_move': 0.0  # not supported
                }
                table.append(item)

            return table

    def get_interfaces_ip(self):
        """Get IP interface IP addresses."""
        "Looks like there's a bug n ArubaOS and is not returning IPv6"

        output = {}
        resp = self.get(self._ipaddresses_url)
        if resp.status_code == 200:
            for address in resp.json().get('ip_address_subnet_element'):
                iface_name = "VLAN" + str(address['vlan_id'])
                if iface_name not in output.keys():
                    output[iface_name] = {}
                ip = IPNetwork("{}/{}".format(
                    address['ip_address']['octets'],
                    address['ip_mask']['octets']))
                version = 'ipv' + str(ip.version)
                if version not in output[iface_name].keys():
                    output[iface_name][version] = {}
                output[iface_name][version][str(ip.ip)] = {
                        'prefix_length': ip.prefixlen}

        return output

    def get_lldp_neighbors(self):
        """Get a list of LLDP neighbors."""
        url = self._api_url + '/lldp/remote-device'
        resp = self.get(url)
        log.debug("API returned {}".format(resp.status_code))

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

    def get_lldp_neighbors_detail(self, *args, **kwargs):
        """Get LLDP neighbor information."""
        url = self._api_url + '/lldp/remote-device'
        resp = self.get(url)
        log.debug("API returned {}".format(resp.status_code))

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

    def get_ntp_peers(self):
        """Get NTP peers."""
        """
        ArubaOS does not support NTP "peers", just upstream servers.
        This method is just an alias of get_ntp_servers()
        """
        self.get_ntp_servers()

    def get_ntp_servers(self):
        """Get NTP servers."""
        " TO-DO: add IPv6 support, currently getting 404 from the API"
        url = self._api_url + 'config/ntp/server/ip4addr'
        resp = self.get(url)
        if resp.status_code == 200:
            output = {}
            for server in resp.json().get('ntpServerIp4addr_element'):
                output[server['ip4addr']['ip4addr_value']] = {}
            return output

    def get_ntp_stats(self):
        """Get NTP peer statistics."""
        out = []
        associations = self.get_ntp_servers()

        for association in associations.keys():
            url = self._api_url + \
                'monitoring/ntp/associations/detail/' + association
            resp = self.get(url)
            if resp.status_code == 200:
                ntp_entry = {
                    'remote': resp.json()['IP Address'],
                    'referenceid': resp.json()['Reference ID'],
                    'stratum': int(resp.json()['Stratum']),
                    'type': resp.json()['Peer Mode'],
                    'when': resp.json()['Origin Time'],
                    'hostpoll': int(resp.json()['Peer Poll Intvl']),
                    'reachability': int(resp.json()['Reach']),
                    'delay': float(resp.json()['Root Delay'].split(' ')[0]),
                    'offset': float(resp.json()['Offset'].split(' ')[0]),
                    'jitter': float(resp.json()['Root Dispersion'].split(' ')[0])
                }

                if resp.json()['Status'].find("Master") == -1:
                    ntp_entry['synchronized'] = False
                else:
                    ntp_entry['synchronized'] = True

                out.append(ntp_entry)

        return out

    def get_optics(self):
        """Transceiver output/input readings. We need to parse CLI."""
        """ CMDs:
         - show interfaces transceiver detail
        """
        return super().get_optics()

    def get_route_to(self, destination='', protocol=''):
        """
        Get route to destination.

        :param destination:
        :param protocol:
        :return:
        """
        if destination:
            ip_address = IPNetwork(destination)

            cmds = {
                4: {
                    'template': 'show_ip_route',
                    'command': 'show ip route {} {}'.format(ip_address.ip, protocol)
                },
                6: {
                    'template': 'show_ipv6_route',
                    'command': 'show ipv6 route {} {}'.format(ip_address.ip, protocol)
                }
            }
            cmd_dict = cmds[ip_address.version]
            ret = self._run_cmd(cmd_dict['command'])

            route_table = textfsm_extractor(self, cmd_dict['template'], ret)
        else:
            cmds = [
                {
                    'template': 'show_ip_route',
                    'command': 'show ip route {} {}'.format(destination, protocol)
                },
                {
                    'template': 'show_ipv6_route',
                    'command': 'show ipv6 route {} {}'.format(destination, protocol)
                }
            ]

            ret = self.cli([cmd['command'] for cmd in cmds])

            route_table = []
            for cmd in cmds:
                route_table.extend(textfsm_extractor(self, cmd['template'], ret[cmd['command']]))

        out = {}
        for route in route_table:
            if not out.get(route['destination']):
                out[route['destination']] = []
            new_path = {
                'protocol': route['type'],
                'preference': int(route['distance']),
                'next_hop': route['gateway']
            }
            out[route['destination']].append(new_path)
        return out

    def _config_batch(self, cmd_list):
        url = self._api_url + 'cli_batch'
        data = {
            'cli_batch_base64_encoded': ArubaOSS._str_to_b64('\n'.join(cmd_list))
        }
        batch_run = self.post(url, json=data)

        if not batch_run.status_code == 202:
            log.debug("Failed to paste commands")

            return False

        check_status = self.get(url + "/status")
        if check_status.status_code == 200:
            for cmd_status in check_status.json()['cmd_exec_logs']:
                if cmd_status['status'] != "CCS_SUCCESS":
                    log.debug("command failed to execute with error {}".format(cmd_status['result']))

                    return False
                else:
                    return True
            return True

    def _backup_config(self, config='running', destination='backup'):
        """Backup config."""
        """Supported configs
        API:
            - "CT_RUNNING_CONFIG",
            - "CT_STARTUP_CONFIG"
        """
        url = self._api_url + 'system/config/cfg_backup_files'
        payload = {}
        if destination == 'backup':
            payload['file_name'] = 'backup_{}'.format(config)
        elif destination == 'REST_Payload_Backup':
            """
            Discard running config by copying running to candidate
            """
            payload['file_name'] = 'REST_Payload_Backup'

        if config == 'running':
            payload['config_type'] = 'CT_RUNNING_CONFIG'
        elif config == 'startup':
            payload['config_type'] = 'CT_STARTUP_CONFIG'
        else:
            "unsupported argument; raise error"
            return False
        cmd_post = self.post(url, json=payload)
        if not cmd_post.ok:
            "raise error"
            pass
        else:
            return cmd_post.json()

    def rollback(self):
        """Rollback configuration."""
        diff = self.compare_config()
        if diff and isinstance(diff, dict):
            if not (
                    len(diff.get('diff_add_list')) and
                    len(diff.get('diff_remove_list'))
            ):
                self._commit_candidate(config='backup_running')

                return True
            else:
                return False

    def traceroute(self, destination, source='', ttl=255, timeout=2, vrf=''):
        """
        Execute traceroute on the device and returns a dictionary with the result.

        :param destination: needed argument
        :param source: not implemented as not available from device
        :param ttl: not implemented as not available from device
        :param timeout: not implemented as not available from device
        :param vrf: not implemented as not available from device
        :return: returns a dictionary containing the hops and probes
        """
        url = self._api_url + 'trace-route'
        data = {"destination": {"ip_address": {"version": "IAV_IP_V4", "octets": destination}}}
        data_post = self.post(url, json=data)

        if not data_post.status_code == 200:
            return {'error': 'unknown host {}'.format(destination)}

        ret = {'success': {}}
        ttl_data = data_post.json().get('ttl_data', [])

        for hop_count in range(len(ttl_data)):
            ret['success'][hop_count + 1] = {'probes': {}}
            ttl_probe_data = ttl_data[hop_count].get('ttl_probe_data', [])
            for probe_count in range(len(ttl_probe_data)):
                try:
                    hostname, _, _ = socket.gethostbyaddr(
                        ttl_probe_data[probe_count].get('gateway', {}).get('ip_address', {}).get('octets', '')
                    )
                except socket.herror:  # fetch if nothing can be found
                    hostname = ''

                probe = {
                    'rtt': float(ttl_probe_data[probe_count]['probe_time_in_millis']),
                    'ip_address':
                        ttl_probe_data[probe_count].get('gateway', {}).get('ip_address', {}).get('octets', ''),
                    'hostname': hostname
                }

                ret['success'][hop_count + 1]['probes'][probe_count + 1] = probe
                del probe

        return ret

    def close(self):
        """Close device connection and delete sessioncookie."""
        rest_logout = self.delete(self._login_url)
        self._apisession.headers['cookie'] = ''

        if not rest_logout.status_code == 204:
            log.debug("Logout Failed")
        else:
            return "logout ok"
