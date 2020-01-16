"""ArubaOS-Switch Napalm driver."""
import logging
import urllib3

from napalm_arubaoss.helper.base import Connection
from napalm_arubaoss.helper import (
    backup_config,
    commit_config,
    compare_config,
    get_mac_address_table,
    get_facts,
    get_arp_table,
    get_config,
    get_interfaces_ip,
    get_lldp_neighbors,
    get_lldp_neighbors_detail,
    get_ntp_stats,
    get_ntp_servers,
    get_route_to,
    load_merge_candidate,
    load_replace_candidate,
    ping,
    rollback,
    traceroute
)

from napalm.base.base import NetworkDriver

logger = logging.getLogger('arubaoss')
logger.setLevel(logging.INFO)

stream_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

streamhandler = logging.StreamHandler()
streamhandler.setFormatter(stream_formatter)
streamhandler.setLevel(logging.INFO)

logger.addHandler(streamhandler)


class ArubaOSS(NetworkDriver):
    """Class for connecting to aruba-os devices using the rest-api."""

    def __init__(
            self,
            hostname,
            username='',
            password='',
            timeout=10,
            optional_args=None
    ):
        """Instantiate the module."""
        if optional_args.get('debugging', False):
            logger.setLevel(logging.DEBUG)
            streamhandler.setLevel(logging.DEBUG)

        if optional_args.get('disable_ssl_warnings', False):
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args

        self.cli_output = {}

        self.connection = Connection()

    def open(self):
        """Open connection to the network device."""
        self.connection.login(
            hostname=self.hostname,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            optional_args=self.optional_args
        )

        return True

    def load_replace_candidate(self, filename=None, config=None):
        """Replace running config with the candidate."""
        """ Implentation of napalm module load_replace_candidate()
        ArubaOS-Switch supports payload_type options:
            - "RPT_PATCH_FILE" -> not implemented
            - "RPT_BACKUP_FILE" -> Implemented

        Note: the maximum content_length = 16072,
        "HTTP/1.1 413 Request Entity Too Large" is returned above that!!!
        """
        ret = load_replace_candidate(filename=filename, config=config)

        return ret

    def load_merge_candidate(self, filename=None, config=None):
        """Merge candidate configuration with the running one."""
        """
        Imperative config change:
         Merge new config with existing one. There's no config validation
         nor atomic commit!. Only configuration commands are supported,
         "configure terminal" is not required. Use with caution.

        """
        ret = load_merge_candidate(filename=filename, config=config)

        return ret

    def cli(self, commands):
        """Run CLI commands through the REST API."""
        ret = self.connection.cli(commands)

        return ret

    def get_arp_table(self, *args, **kwargs):
        """Get device's ARP table."""
        ret = get_arp_table(self_obj=self)

        return ret

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
        ret = get_config(retrieve=retrieve)

        return ret

    def get_facts(self):
        """Get general device information."""
        ret = get_facts()

        return ret

    def discard_config(self):
        """Discard the candidate configuration."""
        backup_config(destination='REST_Payload_Backup')

    def compare_config(self):
        """Compare the running config with the candidate one."""
        ret = compare_config()

        return ret

    def commit_config(self, message=None, confirm=0):
        """Backups and commit the configuration, and handles commit confirm."""
        ret = commit_config(confirm=confirm)

        return ret

    def get_mac_address_table(self):
        """Get the mac-address table of the device."""
        ret = get_mac_address_table()

        return ret

    def get_interfaces_ip(self):
        """Get IP interface IP addresses."""
        "Looks like there's a bug n ArubaOS and is not returning IPv6"
        ret = get_interfaces_ip()

        return ret

    def get_lldp_neighbors(self):
        """Get a list of LLDP neighbors."""
        ret = get_lldp_neighbors()

        return ret

    def get_lldp_neighbors_detail(self, *args, **kwargs):
        """Get LLDP neighbor information."""
        ret = get_lldp_neighbors_detail(*args, **kwargs)

        return ret

    def get_ntp_peers(self):
        """Get NTP peers."""
        """
        ArubaOS does not support NTP "peers", just upstream servers.
        This method is just an alias of get_ntp_servers()
        """
        ret = get_ntp_servers()

        return ret

    def get_ntp_servers(self):
        """Get NTP servers."""
        " TO-DO: add IPv6 support, currently getting 404 from the API"
        ret = get_ntp_servers()

        return ret

    def get_ntp_stats(self):
        """Get NTP peer statistics."""
        ret = get_ntp_stats()

        return ret

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
        ret = get_route_to(
            destination=destination,
            protocol=protocol,
            self_obj=self
        )

        return ret

    def rollback(self):
        """Rollback configuration."""
        ret = rollback()

        return ret

    def traceroute(
            self,
            destination,
            source='',
            ttl=255,
            timeout=2,
            vrf=''
    ):
        """
        Execute traceroute on the device and returns a dictionary with the result.

        :param destination: needed argument
        :param source: not implemented as not available from device
        :param ttl: not implemented as not available from device
        :param timeout: not implemented as not available from device
        :param vrf: not implemented as not available from device
        :return: returns a dictionary containing the hops and probes
        """
        ret = traceroute(destination=destination)
        return ret

    def ping(
            self,
            destination,
            source='',
            timeout=2,
            ttl=255,
            size=100,
            count=5,
            vrf=''
    ):
        """
        Execute ping on the device and returns a dictionary with the result.

        :param destination: needed argument
        :param source: not implemented as not available from device
        :param ttl: not implemented as not available from device
        :param timeout: not implemented as not available from device
        :param vrf: not implemented as not available from device
        :param size: not implemented as not available from device
        :param count: not implemented as not available from device
        :return: returns a dictionary containing the hops and probes
        """
        ret = ping(destination=destination, timeout=timeout)
        return ret

    def close(self):
        """Close device connection and delete sessioncookie."""
        ret = self.connection.logout()
        return ret
