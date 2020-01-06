# Getting started

NOTE: Napalm for ArubaOS Switches only works with python3, make sure to set it as your default python interpreter

## Install ansible and napalm

 ```
pip3 install ansible napalm

 ```

  - Configure ansible 
 ```
 # example ansible.cfg
library = /$HOME/.local/lib/python3.6/site-packages/napalm_ansible/modules
action_plugins = /$HOME/.local/lib/python3.6/site-packages/napalm_ansible/plugins/action
inventory=./inventory
interpreter_python=/usr/bin/python3

 ```

 - populate an inventory file with your devices
 ```
 # example inventory file
 ---
all:
  hosts:
    192.0.2.126:
      user: manager
      passwd: manager
      os: arubaoss
 ```

## Create your playbooks





### get_facts()

 - Sample playbook
 ```
# playbook get_facts.yml
---
- name: GET STRUCTURED DATA BACK FROM CLI DEVICES
  hosts: all
  connection: local
  gather_facts: False

  tasks:

    - name: get facts from device
      napalm_get_facts:
        hostname: "{{ inventory_hostname }}"
        username: "{{ user }}"
        dev_os: "{{ os }}"
        password: "{{ passwd }}"
      register: result
    
    - name: print data
      debug: var=result
 ```
 - to run it

 ```
# ansible-playbook  get_facts.yml

PLAY [GET STRUCTURED DATA BACK FROM CLI DEVICES] ******************************************************************************************************************************************************************

TASK [get facts from device] **************************************************************************************************************************************************************************************
ok: [192.0.2.126]

TASK [print data] *************************************************************************************************************************************************************************************************
ok: [192.0.2.126] => {
    "result": {
        "ansible_facts": {
            "napalm_facts": {
                "fqdn": "2930f-to-be-rolledback2.example.net",
                "hostname": "2930f-to-be-rolledback2",
                "interface_list": [
                    "9",
                    "10",
                    "1",
                    "2",
                    "3",
                    "4",
                    "5",
                    "6",
                    "7",
                    "8"
                ],
                "model": "Aruba2930F-8G-PoE+-2SFP+ Switch(JL258A)",
                "os_version": "WC.16.09.0004",
                "serial_number": "CN93ABC3M1",
                "vendor": "HPE Aruba"
            },
            "napalm_fqdn": "2930f-to-be-rolledback2.example.net",
            "napalm_hostname": "2930f-to-be-rolledback2",
            "napalm_interface_list": [
                "9",
                "10",
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8"
            ],
            "napalm_model": "Aruba2930F-8G-PoE+-2SFP+ Switch(JL258A)",
            "napalm_os_version": "WC.16.09.0004",
            "napalm_serial_number": "CN93ZBC3M1",
            "napalm_vendor": "HPE Aruba"
        },
        "changed": false,
        "failed": false
    }
}

PLAY RECAP ********************************************************************************************************************************************************************************************************
192.0.2.126              : ok=2    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

 ```


 ### cli

  - Sample playbook

```
---
- name: Test Napalm driver
  hosts: all
  connection: local
  gather_facts: False

  tasks:

    - name: run some commands
      napalm_cli:
        hostname: "{{ inventory_hostname }}"
        username: "{{ user }}"
        dev_os: "{{ os }}"
        password: "{{ passwd }}"
        args:
          commands:
            - show interfaces
            - show version
            - show system
      register: result
    
    - name: print data
      debug: var=result

```

 - Run the playbook:
```
# ANSIBLE_STDOUT_CALLBACK=yaml ansible-playbook cli.yml 

PLAY [Test Napalm driver] *****************************************************************************************************************************************************************************************

TASK [run some commands] ******************************************************************************************************************************************************************************************
ok: [192.0.2.126]

TASK [print data] *************************************************************************************************************************************************************************************************
ok: [192.0.2.126] => 
  result:
    changed: false
    cli_results:
      show interfaces: |2+
  
         Status and Counters - Port Counters
  
                                                                         Flow Bcast
          Port         Total Bytes    Total Frames   Errors Rx Drops Tx  Ctrl Limit
          ------------ -------------- -------------- --------- --------- ---- -----
          1            80,485,126     161,407        0         0         off  0
          2            0              0              0         0         off  0
          3            84,403,649     184,732        0         0         off  0
          4            0              0              0         0         off  0
          5            0              0              0         0         off  0
          6            0              0              0         0         off  0
          7            7,476,969      51,735         0         0         off  0
          8            0              0              0         0         off  0
          9            0              0              0         0         off  0
          10           0              0              0         0         off  0
  
      show system: |2+
  
         Status and Counters - General System Information
  
          System Name        : 2930f-to-be-rolledback2
          System Contact     :
          System Location    :
  
          MAC Age Time (sec) : 300
  
          Time Zone          : 0
          Daylight Time Rule : None
  
          Software revision  : WC.16.09.0004        Base MAC Addr      : 3821c7-b93f00
          ROM Version        : WC.16.01.0006        Serial Number      : CN93ABC3M1
  
          Up Time            : 2 hours              Memory   - Total   : 339,763,712
          CPU Util (%)       : 0                               Free    : 220,436,680
  
          IP Mgmt  - Pkts Rx : 9792                 Packet   - Total   : 6600
                     Pkts Tx : 6168                 Buffers    Free    : 4282
                                                               Lowest  : 4270
                                                               Missed  : 0
  
      show version: |2+
  
        Image stamp:    /ws/swbuildm/zootopia_qt_qaoff/code/build/lvm(swbuildm_zootopia_qt_qaoff_zootopia_qt)
                        Aug 22 2019 16:02:59
                        WC.16.09.0004
                        786
        Boot Image:     Primary
  
        Boot ROM Version:    WC.16.01.0006
        Active Boot ROM:     Primary
  
    failed: false

PLAY RECAP ********************************************************************************************************************************************************************************************************
192.0.2.126              : ok=2    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

```


### Install config

 - Sample playbook
 ```
 # playbook install_config.yml
---
- name: Test Napalm driver - configuring a device
  hosts: all
  connection: local
  gather_facts: False

  tasks:
    - name: Load merge new config
      napalm_install_config:
        hostname: "{{ inventory_hostname }}"
        username: "{{ user }}"
        dev_os: "{{ os }}"
        password: "{{ passwd }}"
        config_file: 2930f.conf
        commit_changes: True
        replace_config: False
        get_diffs: True
        diff_file: "{{ inventory_hostname }}-diff"

```
 - Running it
```
ansible-playbook install_config.yml

PLAY [Test Napalm driver - configuring a device] ******************************************************************************************************************************************************************

TASK [Load merge new config] **************************************************************************************************************************************************************************************
ok: [192.0.2.126]

PLAY RECAP ********************************************************************************************************************************************************************************************************
192.0.2.126              : ok=1    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   


```


    
