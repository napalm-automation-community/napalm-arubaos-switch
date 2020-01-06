# Saltstack Examples

## grains.items

```
root@lab-salt-master:/srv# salt '2930f' grains.items
2930f:
    ----------
    cpuarch:
        x86_64
    dns:
        ----------
        domain:
        ip4_nameservers:
            - 127.0.0.53
        ip6_nameservers:
        nameservers:
            - 127.0.0.53
        options:
            - edns0
        search:
            - example.org
            - example.net
        sortlist:
    fqdns:
    gpus:
    host:
        192.0.2.126
    hostname:
        lala
    hwaddr_interfaces:
        ----------
        ens18:
            16:2e:da:49:94:71
        lo:
            00:00:00:00:00:00
    id:
        2930f
    interfaces:
        - 9
        - 10
        - 1
        - 2
        - 3
        - 4
        - 5
        - 6
        - 7
        - 8
    ip4_gw:
        172.16.2.1
    ip6_gw:
        False
    ip_gw:
        True
    kernel:
        proxy
    kernelrelease:
        proxy
    kernelversion:
        proxy
    locale_info:
        ----------
    machine_id:
        55e3c1a944e743f5849262d27a671027
    master:
        lab-salt-master.example.org
    mem_total:
        0
    model:
        Aruba2930F-8G-PoE+-2SFP+ Switch(JL258A)
    nodename:
        salt-minion01
    num_gpus:
        0
    optional_args:
        ----------
        config_lock:
            False
        keepalive:
            5
    os:
        arubaoss
    os_family:
        proxy
    osarch:
        x86_64
    osfinger:
        proxy-proxy
    osfullname:
        proxy
    osrelease:
        proxy
    osrelease_info:
        - proxy
    path:
        /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    ps:
        ps -efHww
    pythonexecutable:
        /usr/bin/python3
    pythonpath:
        - /usr/bin
        - /usr/lib/python36.zip
        - /usr/lib/python3.6
        - /usr/lib/python3.6/lib-dynload
        - /usr/local/lib/python3.6/dist-packages
        - /usr/lib/python3/dist-packages
    pythonversion:
        - 3
        - 6
        - 9
        - final
        - 0
    saltpath:
        /usr/lib/python3/dist-packages/salt
    saltversion:
        2019.2.2
    saltversioninfo:
        - 2019
        - 2
        - 2
        - 0
    serial:
        CN932FKE3M1
    shell:
        /bin/sh
    uptime:
        None
    username:
        manager
    vendor:
        HPE Aruba
    version:
        WC.16.09.0004
    virtual:
        kvm
    zmqversion:
        4.2.5
```


## net.arp
```
root@lab-salt-master:/srv# salt '2930f' net.arp
2930f:
    ----------
    comment:
    out:
        |_
          ----------
          age:
              N/A
          interface:
              3
          ip:
              192.0.2.1
          mac:
              44:31:92:68:76:a3
          type:
              dynamic
        |_
          ----------
          age:
              N/A
          interface:
              3
          ip:
              192.0.2.26
          mac:
              e0:4f:43:8f:06:7a
          type:
              dynamic
        |_
          ----------
          age:
              N/A
          interface:
              1
          ip:
              192.0.2.23
          mac:
              e0:4f:43:8d:2b:8c
          type:
              dynamic
    result:
        True

```

## net.mac

```
root@lab-salt-master:/srv# salt '2930f' net.mac
2930f:
    ----------
    comment:
    out:
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              3c:e1:a1:22:3f:51
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              00:0c:29:67:3c:7b
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:59:57:1f
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              a0:ce:c8:c7:6a:c1
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              50:7b:9d:11:30:de
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e8:f7:24:4e:c3:a7
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              2c:23:3a:53:bf:37
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:8d:35:f7
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              44:31:92:68:76:a3
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:59:2d:c0
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:98:31:ca
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              10:da:43:f9:b4:cf
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:8c:6f:c1
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              54:e1:ad:3c:80:a0
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e8:f7:24:4e:c3:65
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              54:ee:75:c9:52:04
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:8e:23:47
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              00:23:24:c5:13:8f
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              7
          mac:
              40:71:83:21:20:00
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:8f:be:13
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              1
          mac:
              e0:4f:43:8d:2b:8c
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              5c:f9:dd:70:b8:8c
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              4c:cc:6a:c5:cc:25
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              3c:e1:a1:22:76:53
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              3c:e1:a1:23:ba:a9
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              3c:e1:a1:4f:4b:60
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:90:6d:ab
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              3c:e1:a1:23:ba:73
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              3c:07:54:10:83:29
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              3c:e1:a1:50:1e:6e
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:98:2f:73
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              8c:16:45:9c:36:c6
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:8f:06:7a
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:8f:c4:be
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:99:38:0f
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:8a:b1:1c
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              98:5a:eb:d1:96:1d
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              3c:e1:a1:50:1e:c2
          vlan:
              1
        |_
          ----------
          active:
              True
          interface:
              3
          mac:
              e0:4f:43:8b:2b:ca
          vlan:
              1
    result:
        True
```

## net.ipaddrs

```
root@lab-salt-master:/srv# salt '2930f' net.ipaddrs
2930f:
    ----------
    comment:
    out:
        ----------
        VLAN1:
            ----------
            ipv4:
                ----------
                192.0.2.126:
                    ----------
                    prefix_length:
                        22
    result:
        True

```

## net.lldp

```
root@lab-salt-master:/srv# salt '2930f' net.lldp
2930f:
    ----------
    comment:
    out:
        ----------
        3:
            |_
              ----------
              remote_chassis_id:
                  e8 f7 24 4e c3 65
              remote_port:
                  GigabitEthernet1/0/26
              remote_port_description:
                  Guillermo
              remote_system_capab:
                  - bridge
                  - router
              remote_system_description:
                  HPE Comware Platform Software, Software Version 7.1.070, Release 3506
              remote_system_enable_capab:
                  - bridge
                  - router
              remote_system_name:
                  LAS-DS-Z-140
    result:
        True

```

## net.facts

```
root@lab-salt-master:/srv# salt '2930f' net.facts
2930f:
    ----------
    comment:
    out:
        ----------
        fqdn:
            lala.example.org
        hostname:
            lala
        interface_list:
            - 9
            - 10
            - 1
            - 2
            - 3
            - 4
            - 5
            - 6
            - 7
            - 8
        model:
            Aruba2930F-8G-PoE+-2SFP+ Switch(JL258A)
        os_version:
            WC.16.09.0004
        serial_number:
            CN93KSL3M1
        vendor:
            HPE Aruba
    result:
        True

```

## route.show

```
root@lab-salt-master:/srv# salt '2930f' route.show 1.1.1.1
2930f:
    ----------
    comment:
    out:
        ----------
        1.0.0.0/8:
            |_
              ----------
              next_hop:
                  192.0.2.1
              preference:
                  1
              protocol:
                  static
            |_
              ----------
              next_hop:
                  192.0.2.2
              preference:
                  1
              protocol:
                  static
            |_
              ----------
              next_hop:
                  192.0.2.3
              preference:
                  1
              protocol:
                  static
    result:
        True

```

## net.cli

```
root@lab-salt-master:/srv# salt '2930f' net.cli "show system"
2930f:
    ----------
    comment:
    out:
        ----------
        show system:
            
             Status and Counters - General System Information
            
              System Name        : lala                                            
              System Contact     : 
              System Location    : 
            
              MAC Age Time (sec) : 300    
            
              Time Zone          : 0    
              Daylight Time Rule : None                      
            
              Software revision  : WC.16.09.0004        Base MAC Addr      : 3821c7-b93f00    
              ROM Version        : WC.16.01.0006        Serial Number      : CN93HKZ3M1  
            
              Up Time            : 31 days              Memory   - Total   : 339,763,712 
              CPU Util (%)       : 12                              Free    : 217,318,324 
            
              IP Mgmt  - Pkts Rx : 1,480,520            Packet   - Total   : 6600        
                         Pkts Tx : 705,639              Buffers    Free    : 4347        
                                                                   Lowest  : 4262        
                                                                   Missed  : 0           
            
            
    result:
        True

```

## net.config

```
root@lab-salt-master:/srv# salt '2930f' net.config source="running"
2930f:
    ----------
    comment:
    out:
        ----------
        candidate:
        running:
            
            Running configuration:
            
            ; JL258A Configuration Editor; Created on release #WC.16.09.0004
            ; Ver #14:27.6f.f8.1d.9b.3f.bf.bb.ef.7c.59.fc.6b.fb.9f.fc.ff.ff.37.ef:04
            hostname "lala"
            module 1 type jl258a
            no cdp run
            rest-interface session-idle-timeout 7200
            ntp server 162.159.200.123
            web-management ssl
            ip route 0.0.0.0 0.0.0.0 192.0.2.1
            ip route 1.0.0.0 255.0.0.0 192.0.2.1
            ip route 1.0.0.0 255.0.0.0 192.0.2.2
            ip route 1.0.0.0 255.0.0.0 192.0.2.3
            ip routing
            interface 1
               name "PORT1"
               exit
            snmp-server community "public" unrestricted
            vlan 1
               name "DEFAULT_VLAN"
               untagged 1-10
               ip address dhcp-bootp
               ipv6 enable
               ipv6 address dhcp full
               exit
            vlan 12
               name "test"
               no ip address
               exit
            vlan 123
               name "VLAN123--"
               no ip address
               exit
            vlan 1234
               name "VLAN1234"
               no ip address
               exit
            no tftp server
            no autorun
            no dhcp config-file-update
            no dhcp image-file-update
            no dhcp tr69-acs-url
            
            
        startup:
    result:
        True

```

## net.load_config

```
root@lab-salt-master:/srv# salt '2930f' net.load_config filename='salt://config.txt' replace=True commit=False
2930f:
    ----------
    already_configured:
        False
    comment:
    diff:
        ----------
        diff_add_list:
            - hostname "2930f-to-be-rolledback2"
        diff_file_name:
            backup_running
        diff_remove_list:
            - hostname "lala"
            - no cdp run
            - ip route 1.0.0.0 255.0.0.0 192.0.2.1
            - ip route 1.0.0.0 255.0.0.0 192.0.2.2
            - ip route 1.0.0.0 255.0.0.0 192.0.2.3
        uri:
            /system/config/cfg_restore/latest_diff/status
    loaded_config:
    result:
        True
root@lab-salt-master:/srv# salt '2930f' net.load_config filename='salt://config.txt' replace=True commit=True
2930f:
    ----------
    already_configured:
        False
    comment:
    diff:
        ----------
        diff_add_list:
            - hostname "2930f-to-be-rolledback2"
        diff_file_name:
            backup_running
        diff_remove_list:
            - hostname "lala"
            - no cdp run
            - ip route 1.0.0.0 255.0.0.0 192.0.2.1
            - ip route 1.0.0.0 255.0.0.0 192.0.2.2
            - ip route 1.0.0.0 255.0.0.0 192.0.2.3
        uri:
            /system/config/cfg_restore/latest_diff/status
    loaded_config:
    result:
        True
root@lab-salt-master:/srv# salt '2930f' net.load_config filename='salt://config.txt' replace=True commit=True
2930f:
    ----------
    already_configured:
        True
    comment:
        Already configured.
    diff:
    loaded_config:
    result:
        True

```

## ntp.servers

```
root@lab-salt-master:/srv# salt '2930f' ntp.servers
2930f:
    ----------
    comment:
    out:
        - 162.159.200.123
    result:
        True

```

## napalm.compliance_report
```
root@lab-salt-master:/srv/salt# salt -G 'os:arubaoss' napalm.compliance_report salt://validate.yaml 
2930m:
    ----------
    comment:
    out:
        ----------
        complies:
            False
        get_facts:
            ----------
            complies:
                False
            extra:
            missing:
                - os_version
            present:
                ----------
        skipped:
    result:
        True
2930f:
    ----------
    comment:
    out:
        ----------
        complies:
            True
        get_facts:
            ----------
            complies:
                True
            extra:
            missing:
            present:
                ----------
                os_version:
                    ----------
                    complies:
                        True
                    nested:
                        False
        skipped:
    result:
        True

```
