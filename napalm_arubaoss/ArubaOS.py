"""ArubaOS-Switch Napalm driver."""
import base64
from itertools import zip_longest
from time import sleep

import requests
import logging
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

    def __init__(self, hostname,
                 username='',
                 password='',
                 timeout=10,
                 optional_args=None):
        """Instantiate the module."""
        self._headers = {'Content-Type': 'application/json'}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        # ----------------------------------------------------------------------------------------
        # optional arguments
        # ----------------------------------------------------------------------------------------
        if optional_args is None:
            optional_args = {}

        self.api = optional_args.get("api", "v6")
        ssl = optional_args.get("ssl", True)
        self.keepalive = optional_args.get("keepalive", None)
        self.ssl_verify = optional_args.get("ssl_verify", False)
        if ssl:
            self.proto = 'https'
        else:
            self.proto = 'http'

        # URL encoding

        self._api_url = '{}://{}/rest/{}/'.format(self.proto,
                                                  self.hostname,
                                                  self.api)

    def open(self):
        """Open connection to the network device."""
        self._login_url = self._api_url + "login-sessions"

        params = {'userName': self.username, 'password': self.password}
        self._apisession = requests.Session()

        if not self.ssl_verify:
            self._apisession.verify = False

        self._apisession.headers = self._headers
        # bug #4 - random delay while re-using TCP connection - workaroud:
        if self.keepalive is None:
            self._apisession.keep_alive = False

        rest_login = self._apisession.post(self._login_url, json=params,
                                           timeout=self.timeout)

        if rest_login.status_code == 201:
            session = rest_login.json()
            self._headers['cookie'] = session['cookie']
            return True
        else:
            raise ConnectAuthError("Login failed")

    def is_alive(self):
        """Check if device connection is alive."""
        """check if session cookie is still valid
        Returns:
            True - Session cookie is still valid
            None - There's an error
        """
        url = self._api_url + 'system'
        endpoint = self._apisession.get(url)
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
            call = self._apisession.get(url)
            if 300 > call.status_code >= 200:
                status = call.json()
                return call
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
            load = self._apisession.post(url, json=payload)
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
        output = {}
        if isinstance(commands, list):
            for cmd in commands:
                output[cmd] = str(self._run_cmd(cmd))
            return output
        elif isinstance(commands, str):
            cmd_list = commands.splitlines()
            return self.cli(cmd_list)

    def get_arp_table(self):
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

    def get_config(self, retrieve="all"):
        """Get configuration stored on the device."""
        out = {'startup': '', 'candidate': '', 'running': ''}

        if (retrieve == 'all' or retrieve == 'startup'):
            out['startup'] = str(self._run_cmd("display saved-configuration"))
        if (retrieve == 'all' or retrieve == 'running'):
            out['running'] = str(self._run_cmd("show running-config"))
        if (retrieve == 'all' or retrieve == 'candidate'):
            out['candidate'] = str(self._run_cmd(
                                "show config REST_Payload_Backup"))
        return out

    def get_facts(self):
        """Get general device information."""
        out = {'vendor': 'HPE Aruba'}
        out['interface_list'] = []

        url = self._api_url + 'system/status'
        call = self._apisession.get(url)
        if 300 > call.status_code >= 200:
            rest_out = call.json()
            out['hostname'] = rest_out['name']
            out['os_version'] = rest_out['firmware_version']
            out['serial_number'] = rest_out['serial_number']
            out['model'] = rest_out['product_model']

            # get domain name to generate the FQDN
            url = self._api_url + 'dns'
            call = self._apisession.get(url)
            if 300 > call.status_code >= 200:
                rest_out = call.json()
                out['fqdn'] = out['hostname'] + "." + \
                    rest_out['dns_domain_names'][0]

        # Get interface list
        url = self._api_url + 'system/status/switch'
        call = self._apisession.get(url)
        if 300 > call.status_code >= 200:
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
        diff = self._apisession.post(url, json=data)
        if 300 > diff.status_code >= 200:
            diff_output = self._apisession.get(check_url)
            if diff_output.status_code == 200:
                if not diff_output.json()['diff_add_list'] and \
                        not diff_output.json()['diff_remove_list']:
                    # return empty string to signal the candidate
                    # and running configs are the same
                    return ""
                else:
                    return diff_output.json()
            else:
                raise CommandErrorException("diff generation failed,\
                    raise status")
        else:
            raise CommandErrorException("diff generation failed, raise status")

    def commit_config(self, message=None, confirm=0):
        """Backups and commit the configuration, and handles commit confirm."""
        self._backup_config()
        log.debug("Confirm rollback time is {}".format(str(confirm)))
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
        cmd_post = self._apisession.post(url, json=data)

        if not cmd_post.json()['failure_reason']:
            check_url = url + '/status'
            return self._transaction_status(check_url).json()

    def get_mac_address_table(self):
        """Get the mac-address table of the device."""
        url = self._api_url + 'mac-table'
        resp = self._apisession.get(url)
        if resp.status_code == 200:
            table = []
            for entry in resp.json().get('mac_table_entry_element'):
                item = {}
                item['mac'] = self._mac_reformat(entry['mac_address'])
                item['interface'] = entry['port_id']
                item['vlan'] = entry['vlan_id']
                item['active'] = True
                """ Not supported:
                item['static'] = False
                item['moves'] = 0
                item['last_move'] = 0.0
                """
                table.append(item)
            return table

    def get_interfaces_ip(self):
        """Get IP interface IP addresses."""
        url = self._api_url + 'ipaddresses'
        url = self._api_url + 'ipaddresses'
        "Looks like there's a bug n ArubaOS and is not returning IPv6"

        resp = self._apisession.get(url)
        if resp.status_code == 200:
            output = {}
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
        resp = self._apisession.get(url)
        log.debug("API returned {}".format(resp.status_code))
        if 300 > resp.status_code >= 200:
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

    def get_lldp_neighbors_detail(self):
        """Get LLDP neighbor information."""
        url = self._api_url + '/lldp/remote-device'
        resp = self._apisession.get(url)
        log.debug("API returned {}".format(resp.status_code))
        if 300 > resp.status_code >= 200:
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
        resp = self._apisession.get(url)
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
            resp = self._apisession.get(url)
            if resp.status_code == 200:
                ntp_entry = {}
                ntp_entry['remote'] = resp.json()['IP Address']
                ntp_entry['referenceid'] = resp.json()['Reference ID']

                if resp.json()['Status'].find("Master") == -1:
                    ntp_entry['synchronized'] = False
                else:
                    ntp_entry['synchronized'] = True

                ntp_entry['stratum'] = int(resp.json()['Stratum'])
                ntp_entry['type'] = resp.json()['Peer Mode']
                ntp_entry['when'] = resp.json()['Origin Time']
                ntp_entry['hostpoll'] = int(resp.json()['Peer Poll Intvl'])
                ntp_entry['reachability'] = int(resp.json()['Reach'])
                ntp_entry['delay'] = \
                    float(resp.json()['Root Delay'].split(' ')[0])
                ntp_entry['offset'] = \
                    float(resp.json()['Offset'].split(' ')[0])
                ntp_entry['jitter'] = \
                    float(resp.json()['Root Dispersion'].split(' ')[0])
                out.append(ntp_entry)
        return out

    def get_optics(self):
        """Transceiver output/input readings. We need to parse CLI."""
        """ CMDs:
         - show interfaces transceiver detail
        """
        return super().get_optics()

    def get_route_to(self, destination='', protocol=''):
        """Get active route for a given destination."""
        v4_table = []
        v6_table = []
        if destination != '':
            ip_address = IPNetwork(destination)
            if ip_address.version == 4:
                raw_v4_table = self._run_cmd(
                    "show ip route {} {}".format(protocol, ip_address.ip))
                v4_table = textfsm_extractor(
                    self, "show_ip_route", raw_v4_table)
            elif ip_address.version == 6:
                raw_v6_table = self._run_cmd(
                    "show ipv6 route {} {}".format(protocol, ip_address.ip))
                v6_table = textfsm_extractor(
                    self, "show_ipv6_route", raw_v6_table)
        else:
            raw_v4_table = self._run_cmd(
                "show ip route {} {}".format(protocol, destination))
            v4_table = textfsm_extractor(
                self, "show_ip_route", raw_v4_table)
            raw_v6_table = self._run_cmd(
                "show ipv6 route {} {}".format(protocol, destination))
            v6_table = textfsm_extractor(self, "show_ipv6_route", raw_v6_table)
        route_table = v4_table + v6_table

        out = {}
        for route in route_table:
            if not out.get(route['destination']):
                out[route['destination']] = []
            new_path = {}
            new_path['protocol'] = route['type']
            new_path['preference'] = int(route['distance'])
            new_path['next_hop'] = route['gateway']
            out[route['destination']].append(new_path)
        return out

    def _run_cmd(self, cmd):
        url = self._api_url + 'cli'
        data = {}
        data['cmd'] = cmd
        cmd_post = self._apisession.post(url, json=data)
        if cmd_post.status_code == 200:
            return base64.b64decode(
                cmd_post.json()['result_base64_encoded']).decode('utf-8')
        else:
            raise CommandErrorException("Parsing CLI commands failed")

    def _config_batch(self, cmd_list):
        url = self._api_url + 'cli_batch'
        data = {}
        data['cli_batch_base64_encoded'] = ArubaOSS._str_to_b64(
                                            '\n'.join(cmd_list))
        batch_run = self._apisession.post(url, json=data)
        if batch_run.status_code == 202:
            check_status = self._apisession.get(url + "/status")
            if check_status.status_code == 200:
                for cmd_status in check_status.json()['cmd_exec_logs']:
                    if cmd_status['status'] != "CCS_SUCCESS":
                        log.debug("command failed to execute with error \
                                 {}".format(cmd_status['result']))
                        return False
                    else:
                        return True
                return True
        else:
            log.debug("Failed to paste commands")
            return False

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
        cmd_post = self._apisession.post(url, json=payload)
        if not 300 > cmd_post.status_code >= 200:
            "raise error"
            pass
        else:
            return cmd_post.json()

    def rollback(self):
        """Rollback configuration."""
        diff = self.compare_config()
        if diff != '' and isinstance(diff, dict):
            if not (len(diff.get('diff_add_list'))
                    and len(diff.get('diff_remove_list'))):
                self._commit_candidate(config='backup_running')
                return True
            else:
                return False

    def close(self):
        """Close device connection and delete sessioncookie."""
        rest_logout = self._apisession.delete(self._login_url)
        self._headers['cookie'] = ''

        if rest_logout.status_code != 204:
            log.debug("Logout Failed")
        else:
            return "logout ok"
