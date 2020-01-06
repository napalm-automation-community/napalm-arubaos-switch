# Napalm-arubaoss
Driver implementation for Aruba OS Switch. Tested in AOS > WC.16.09.0004, some modules may not work properly in older versions.

## Currently supported Napalm methods
    * cli()                           ✅
    * close()                         ✅
    * commit_config()                 ✅
    * compare_config()                ✅
    * compliance_report()             ✅
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
git clone https://github.com/napalm-automation-community/napalm-arubaos-switch
cd napalm-arubaoss-switch
pip3 install .
```

### Switch configuration
This driver relies exclusively on the REST API of Aruba Switches, and it needs to be enabled beforehand.
To enable the REST API in the switch, just run:
```
web-management ssl
rest-interface
rest-interface session-idle-timeout 120 #optional
```

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

 - [grains.items](docs/saltstack.md#grains.items)
 - [net.arp](docs/saltstack.md#net.arp)
 - [net.mac](docs/saltstack.md#net.mac)
 - [net.ipaddrs](docs/saltstack.md#net.ipaddrs)
 - [net.lldp](docs/saltstack.md#net.lldp)
 - [net.facts](docs/saltstack.md#net.facts)
 - [net.ping](docs/saltstack.md#net.ping)
 - [net.traceroute](docs/saltstack.md#net.traceroute)
 - [route.show](docs/saltstack.md#route.show)
 - [net.cli](docs/saltstack.md#net.cli)
 - [net.config](docs/saltstack.md#net.config)
 - [net.load_config](docs/saltstack.md#net.load_config)
 - [net.compare_config](docs/saltstack.md#net.load_config)
 - net.load_template ( Issue #18)
 - net.discard_config
 - [ntp.servers](docs/saltstack.md#ntp.servers)
 - [napalm.compliance_report](docs/saltstack.md#napalm.compliance_report)

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

