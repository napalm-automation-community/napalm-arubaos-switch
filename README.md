[![PyPI](https://img.shields.io/pypi/v/napalm-arubaos-switch.svg)](https://pypi.python.org/pypi/napalm-arubaos-switch)
[![PyPI](https://img.shields.io/pypi/dm/napalm-arubaos-switch.svg)](https://pypi.python.org/pypi/napalm-arubaos-switch)
[![Building Status](https://github.com/napalm-automation-community/napalm-arubaos-switch/workflows/Python%20package/badge.svg?branch=master)](https://github.com/napalm-automation-community/napalm-arubaos-switch/actions?query=workflow%3A"Python%20package")
# Napalm-arubaoss
Driver implementation for Aruba OS Switch. Tested in AOS > WC.16.09.0004, some modules may not work properly in older versions.

## Currently supported Napalm methods
    * cli()                           ✅
    * close()                         ✅
    * commit_config()                 ✅
    * compare_config()                ✅
    * compliance_report()             ✅
    * confirm_commit()                ✅
    * discard_config()                ✅  
    * get_arp_table()                 ✅
    * get_bgp_config()                ❌*
    * get_bgp_neighbors()             ❌*
    * get_bgp_neighbors_detail()      ❌*
    * get_config()                    ✅
    * get_environment()               ❌  - Planned
    * get_facts()                     ✅
    * get_firewall_policies()         ❌*
    * get_interfaces_counters()       ❌***
    * get_interfaces()                ✅
    * get_interfaces_ip()             ✅
    * get_ipv6_neighbors_table()      ❌*
    * get_lldp_neighbors()            ✅
    * get_lldp_neighbors_detail()     ✅
    * get_network_instances()         ❌*
    * get_mac_address_table()         ✅
    * get_ntp_peers()                 ✅
    * get_ntp_servers()               ✅
    * get_ntp_stats()                 ✅
    * get_optics()                    ❌  - Planned
    * get_probes_*()                  ❌*
    * get_route_to()                  ✅
    * get_snmp_information()          ❌  - Planned
    * get_users()                     ❌  - Planned
    * has_pending_commit()            ✅
    * is_alive()                      ✅
    * load_merge_candidate()          ✅**
    * load_replace_candidate()        ✅
    * load_template()                 ✅
    * open()                          ✅
    * ping()                          ✅
    * rollback()                      ✅
    * traceroute()                    ✅

\* N/A - not supported on the tested ArubaOS devices

\*\* Incomplete support for load merge, configuration is directly pushed to the running config. Not recommended, use with precaution !!!

\*\*\* No easy way to get this. API does not support it and there's no single command to display it for all ports

## Getting Started


### Prerequisites

The following software is required:
 - Python3
 - Pip
 - Python modules specified in `requirements.txt`



### Installing

To install simply run:
```
pip3 install napalm-arubaos-switch
```

### Switch configuration
This driver relies exclusively on the REST API of Aruba Switches, and it needs to be enabled beforehand.
To enable the REST API in the switch, just run:
```
web-management ssl
rest-interface
rest-interface session-idle-timeout 120 #optional
```

### optional_args
optional_args can be set during initialization like this:
```Python
from napalm import get_network_driver

d = get_network_driver("arubaoss")

with d('1.2.3.4', 'username', 'password', optional_args={'ssl_verify': False, "debugging": True}) as aruba:
   print(aruba.get_config())
```

The following values can be set in optional_args:
- ssl_verify: bool/str = defaults to **True** - will be passed to the requests object (description can be found [here](https://docs.python-requests.org/en/latest/_modules/requests/sessions/#Session.request))
- keepalive: bool = defaults to **False** - sets the underlying TCP connection to either keep the connection or not and is a workaround for an issue with ArubaOS devices 
  (discussed [here](https://community.arubanetworks.com/community-home/digestviewer/viewthread?MID=28798#bme4aa3703-e476-4880-9cb4-9b208f86b2f4))
- keep_alive: bool = same as keepalive, just shadows it to be able to use the same keyword as in older Python requests versions
- debugging: bool = defaults to **False** - sets the level of the logging handler to logging.DEBUG
- disable_ssl_warnings: bool = defaults to **False** - disables ssl warnings from urllib3
- api: string = defaults to **v6** - defines the API version
- ssl: bool = defaults to **True**, sets http or https

### Saltstack
To use the driver with Saltstack, you would typically need a proxy minion.

#### Proxy minion configuration:
Example pillar's config:

```
proxy:
  proxytype: napalm
  driver: arubaoss
  host: 192.0.2.1
  username: manager
  password: manager
```

#### Proxy `/etc/salt/proxy`

```
master: lab-salt-master
mine_enabled: true # not required, but nice to have

```

#### Supported Salt execution modules

 - [grains.items](docs/saltstack.md#grainsitems)
 - [net.arp](docs/saltstack.md#netarp)
 - [net.mac](docs/saltstack.md#netmac)
 - [net.ipaddrs](docs/saltstack.md#netipaddrs)
 - [net.lldp](docs/saltstack.md#netlldp)
 - [net.facts](docs/saltstack.md#netfacts)
 - [net.ping](docs/saltstack.md#netping)
 - [net.traceroute](docs/saltstack.md#nettraceroute)
 - [route.show](docs/saltstack.md#routeshow)
 - [net.cli](docs/saltstack.md#netcli)
 - [net.config](docs/saltstack.md#netconfig)
 - [net.load_config](docs/saltstack.md#netload_config)
 - [net.compare_config](docs/saltstack.md#netload_config)
 - net.load_template ( Issue #18)
 - net.discard_config
 - [ntp.servers](docs/saltstack.md#ntpservers)
 - [napalm.compliance_report](docs/saltstack.md#napalmcompliance_report)

More details in [Saltstack examples](docs/saltstack.md)


### Ansible

How to get it running with ansible and some examples are in the [Ansible docs](docs/ansible.md)

## Running the tests

**TBD**: Explain how to run the automated tests for this system


## Contributing

Please read [CONTRIBUTING](CONTRIBUTING.md) for details on our process for submitting pull requests to us, and please ensure
you follow the [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md).

## Versioning

**TBD**


## Authors

* **Guillermo Cotone** - [@gcotone](https://github.com/gcotone)

See also the list of [contributors](CONTRIBUTORS.md) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

