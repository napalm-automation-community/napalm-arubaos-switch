"""ArubaOS-Switch Napalm driver."""
import logging
import urllib3

from napalm_arubaoss.helper.base import Connection
from napalm_arubaoss.helper import (
    backup_config,
    commit_config,
    compare_config,
    confirm_commit,
    get_mac_address_table,
    get_facts,
    get_arp_table,
    get_config,
    get_interfaces,
    get_interfaces_ip,
    get_lldp_neighbors,
    get_lldp_neighbors_detail,
    get_ntp_stats,
    get_ntp_servers,
    get_route_to,
    has_pending_commit,
    is_alive,
    load_merge_candidate,
    load_replace_candidate,
    ping,
    rollback,
    traceroute,
)

from napalm.base.base import NetworkDriver

logger = logging.getLogger("arubaoss")
logger.setLevel(logging.INFO)

stream_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

streamhandler = logging.StreamHandler()
streamhandler.setFormatter(stream_formatter)
streamhandler.setLevel(logging.INFO)

logger.addHandler(streamhandler)


class ArubaOSS(NetworkDriver):
    """Class for connecting to aruba-os devices using the rest-api."""

    def __init__(
            self,
            hostname,
            username,
            password,
            timeout=60,
            optional_args=None
    ):
        """
        Initialize Class ArubaOSS.

        :param hostname: Hostname of the device
        :param username: Username for the login
        :param password: Password for the login
        :param timeout: timeout to be passed to Request-Futures
        :param optional_args: Optional Args to be passed to Request-Futures
        """
        if not optional_args:
            optional_args = {}

        if optional_args.get("debugging", False):
            logger.setLevel(logging.DEBUG)
            streamhandler.setLevel(logging.DEBUG)

        if optional_args.get("disable_ssl_warnings", False):
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args

        self.cli_output = {}

        self.connection = Connection()

    def cli(self, commands):
        """
        Run CLI commands through the REST API.

        :param commands:
        :return:
        """
        ret = self.connection.cli(commands)

        return ret

    def close(self):
        """
        Close device connection and delete sessioncookie.

        :return:
        """
        ret = self.connection.logout()

        return ret

    def commit_config(self, message="", revert_in=None):
        """
        Backups and commit the configuration, and handles commit confirm.

        :param message:
        :param revert_in:
        :return:
        """
        ret = commit_config(self=self, revert_in=revert_in)

        return ret

    def compare_config(self):
        """
        Compare the running config with the candidate one.

        :return:
        """
        ret = compare_config(self=self)

        return ret

    def compliance_report(self, validation_file=None, validation_source=None):
        """
        Get Compliance report - NOT IMPLEMENTED.

        :param validation_file:
        :param validation_source:
        :return:
        """
        return super(ArubaOSS, self).compliance_report()

    def confirm_commit(self):
        """
        Confirm the changes requested via commit_config when commit_confirm=True.

        Should cause self.has_pending_commit to return False when done.
        :return: None
        """
        return confirm_commit(self=self)

    def connection_tests(self):
        """
        Show connection tests - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).connection_tests()

    def discard_config(self):
        """
        Discard the candidate configuration.

        :return:
        """
        if self.has_pending_commit():
            self.load_merge_candidate(config="no job ROLLBACK")

        backup_config(self=self, destination="REST_Payload_Backup")

    def get_arp_table(self, vrf=""):
        """
        Get device's ARP table.

        :param vrf:
        :return:
        """
        ret = get_arp_table(self=self, vrf=vrf)

        return ret

    def get_bgp_config(self, group="", neighbor=""):
        """
        Get BGP config - NOT IMPLEMENTED.

        :param group:
        :param neighbor:
        :return:
        """
        return super(ArubaOSS, self).get_bgp_config()

    def get_bgp_neighbors(self):
        """
        Get BGP neighbors - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).get_bgp_neighbors()

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """
        Get BGP Neighbors detail - NOT IMPLEMENTED.

        :param neighbor_address:
        :return:
        """
        return super(ArubaOSS, self).get_bgp_neighbors_detail()

    def get_config(self, retrieve="all", full=False, sanitized=False):
        """
        Get configuration stored on the device.

        :param retrieve:
        :param full:
        :param sanitized:
        :return:
        """
        # TODO check why "full" exists
        ret = get_config(self=self, retrieve=retrieve)

        return ret

    def get_environment(self):
        """
        Get environment readings - NOT IMPLEMENTED.

        Currently (API v7) the API does not support reading information about
        fans, temperature, power or CPU.
        A textfsm template needs to be created to parse:
         - show system temperature
         - show system fan
         - show system power-consumption
         - show system power-supply
         - show system information (CPU/MEM)

        :return:
        output = {
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {},
            "memory": {}
        }
        """
        return super(ArubaOSS, self).get_environment()

    def get_facts(self):
        """
        Get general device information.

        :return:
        """
        ret = get_facts(self=self)

        return ret

    def get_firewall_policies(self):
        """
        Get firewall policies - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).get_firewall_policies()

    def get_interfaces(self):
        """
        Return a dictionary of dictionaries. The keys for the first dictionary will be the \
        interfaces in the devices. The inner dictionary will contain the following data for \
        each interface.

         * is_up (True/False)
         * is_enabled (True/False)
         * description (string)
         * last_flapped (float in seconds) - NOT IMPLEMENTED (always -1.0)
         * speed (int in Mbit)
         * MTU (in Bytes) - NOT IMPLEMENTED (always -1)
         * mac_address (string)

        Example::

            {
            u'Management1':
                {
                'is_up': False,
                'is_enabled': False,
                'description': '',
                'last_flapped': -1.0,
                'speed': 1000,
                'mtu': 1500,
                'mac_address': 'FA:16:3E:57:33:61',
                },
            u'Ethernet1':
                {
                'is_up': True,
                'is_enabled': True,
                'description': 'foo',
                'last_flapped': 1429978575.1554043,
                'speed': 1000,
                'mtu': 1500,
                'mac_address': 'FA:16:3E:57:33:62',
                },
            u'Ethernet2':
                {
                'is_up': True,
                'is_enabled': True,
                'description': 'bla',
                'last_flapped': 1429978575.1555667,
                'speed': 1000,
                'mtu': 1500,
                'mac_address': 'FA:16:3E:57:33:63',
                },
            u'Ethernet3':
                {
                'is_up': False,
                'is_enabled': True,
                'description': 'bar',
                'last_flapped': -1.0,
                'speed': 1000,
                'mtu': 1500,
                'mac_address': 'FA:16:3E:57:33:64',
                }
            }
        """
        ret = get_interfaces(self)

        return ret

    def get_interfaces_counters(self):
        """
        Get interfaces counters - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).get_interfaces_counters()

    def get_interfaces_ip(self):
        """
        Get IP interface IP addresses.

        Looks like there's a bug on ArubaOS and is not returning IPv6

        :return:
        """
        ret = get_interfaces_ip(self=self)

        return ret

    def get_ipv6_neighbors_table(self):
        """
        Get IPv6 neighbors table - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).get_ipv6_neighbors_table()

    def get_lldp_neighbors(self):
        """
        Get a list of LLDP neighbors.

        :return:
        """
        ret = get_lldp_neighbors(self=self)

        return ret

    def get_lldp_neighbors_detail(self, interface=""):
        """
        Get LLDP neighbor information.

        NOTE: Parent Interface is always empty,
        as the information isn't available.

        :param interface:
        :return:
        """
        ret = get_lldp_neighbors_detail(self=self, interface=interface)

        return ret

    def get_mac_address_table(self):
        """
        Get the mac-address table of the device.

        "static", "moves" and "last_move" have always default values,
        as there is no helpful information from the device.

        static: False,  # not supported
        moves: 0,  # not supported
        last_move: 0.0  # not supported

        :return:
        """
        ret = get_mac_address_table(self=self)

        return ret

    def get_network_instances(self, name=""):
        """
        Get network instances - NOT IMPLEMENTED.

        :param name:
        :return:
        """
        return super(ArubaOSS, self).get_network_instances()

    def get_ntp_peers(self):
        """
        Get NTP peers.

        ArubaOS does not support NTP "peers", just upstream servers.
        This method is just an alias of get_ntp_servers()

        :return:
        """
        ret = get_ntp_servers(self=self)

        return ret

    def get_ntp_servers(self):
        """
        Get NTP servers.

        TO-DO: add IPv6 support, currently getting 404 from the API

        :return:
        """
        ret = get_ntp_servers(self=self)

        return ret

    def get_ntp_stats(self):
        """
        Get NTP peer statistics.

        :return:
        """
        ret = get_ntp_stats(self=self)

        return ret

    def get_optics(self):
        """
        Transceiver output/input readings. We need to parse CLI.

        CMDs:
         - show interfaces transceiver detail

        :return:
        """
        return super(ArubaOSS, self).get_optics()

    def get_probes_config(self):
        """
        Get probes config - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).get_probes_config()

    def get_probes_results(self):
        """
        Get probes results - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).get_probes_results()

    def get_route_to(self, destination="", protocol="", longer=False):
        """
        Get route to destination.

        :param destination:
        :param protocol:
        :param longer:
        :return:
        """
        ret = get_route_to(
            self=self,
            destination=destination,
            protocol=protocol
        )

        return ret

    def get_snmp_information(self):
        """
        Get SNMP information - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).get_snmp_information()

    def get_users(self):
        """
        Get users - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).get_users()

    def has_pending_commit(self):
        """
        Boolean indicates if a commit_config that needs confirmed is in process.

        :return Boolean
        """
        return has_pending_commit(self=self)

    def is_alive(self):
        """
        Is alive method.

        :return:
        """
        ret = is_alive(self=self)

        return ret

    def load_merge_candidate(self, filename=None, config=None):
        """
        Merge candidate configuration with the running one.

        Imperative config change:
         Merge new config with existing one. There's no config validation
         nor atomic commit!. Only configuration commands are supported,
         "configure terminal" is not required. Use with caution.

        :param filename:
        :param config:
        :return:
        """
        ret = load_merge_candidate(
            self=self, filename=filename, config=config
        )

        return ret

    def load_replace_candidate(self, filename=None, config=None):
        """
        Replace running config with the candidate.

        Implentation of napalm module load_replace_candidate()
        ArubaOS-Switch supports payload_type options:
            - "RPT_PATCH_FILE" -> not implemented
            - "RPT_BACKUP_FILE" -> Implemented

        Note: the maximum content_length = 16072,
        "HTTP/1.1 413 Request Entity Too Large" is returned above that!!!

        :param filename:
        :param config:
        :return:
        """
        ret = load_replace_candidate(
            self=self, filename=filename, config=config
        )

        return ret

    def load_template(
        self, template_name, template_source=None, template_path=None, **template_vars
    ):
        """
        Load template - NOT IMPLEMENTED.

        :param template_name:
        :param template_source:
        :param template_path:
        :param template_vars:
        :return:
        """
        return super(ArubaOSS, self).load_template()

    def open(self):
        """
        Open connection to the network device.

        :return:
        """
        self.connection.login(
            hostname=self.hostname,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            optional_args=self.optional_args,
        )

        return True

    def ping(
        self,
        destination,
        source="",
        ttl=255,
        timeout=2,
        size=100,
        count=5,
        vrf="",
        source_interface=""
    ):
        """
        Execute ping on the device and returns a dictionary with the result.

        :param destination: needed argument
        :param source: not implemented as not available from device
        :param ttl: not implemented as not available from device
        :param timeout: Maximum seconds to wait after sending final packet
        :param vrf: not implemented as not available from device
        :param size: not implemented as not available from device
        :param count: not implemented as not available from device
        :param source_interface: not  implemented as not available from device
        :return: returns a dictionary containing the hops and probes
        """
        ret = ping(self=self, destination=destination, timeout=timeout)
        return ret

    def post_connection_tests(self):
        """
        Post connection tests - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).post_connection_tests()

    def pre_connection_tests(self):
        """
        Pre connection tests - NOT IMPLEMENTED.

        :return:
        """
        return super(ArubaOSS, self).pre_connection_tests()

    def rollback(self):
        """
        Rollback configuration.

        :return:
        """
        ret = rollback(self=self)

        return ret

    def traceroute(self, destination, source="", ttl=255, timeout=2, vrf=""):
        """
        Execute traceroute on the device.

        :param destination: needed argument
        :param source: not implemented as not available from device
        :param ttl: not implemented as not available from device
        :param timeout: not implemented as not available from device
        :param vrf: not implemented as not available from device
        :return: returns a dictionary containing the hops and probes
        """
        ret = traceroute(self=self, destination=destination)

        return ret
