"""
Utilities to support the main class.

It is doing the parsing of strings and
is filling the dictionary which gets returned
by the main class method.
"""
import re


def get_interface_list(cli_ret):
    """
    Return the interfaces-list from the parsed raw data.

    :param cli_ret: the raw return from the cli endpoint
    :return: interfaces-list (list)
    """
    re_interfaces = r'\n\s*(\d+)'
    return re.findall(re_interfaces, cli_ret)


def get_interface_details(cli_ret):
    """
    Return the interface-details from the parsed raw data.

    :param cli_ret: the raw return from the cli endpoint
    :return: interface-details (list)
    """
    re_int_details = r'([/\w()]+[ /\w()]+[/\w()]+)\s+:\s([a-zA-Z0-9-.,]+)'
    return re.findall(re_int_details, cli_ret)


def fill_interface_dict(data):
    """
    Fill the Dict-Template which will be returned by the main method.

    :param data: the tuple with data
    :return: dictionary
    """
    ret = {}
    data_dict = {entry[0]: entry[1] for entry in data}

    mac = data_dict.get('MAC Address', '')
    mac = ''.join(c.upper() for c in mac if c.isalnum())
    mac = ':'.join(mac[i:i + 2] for i in range(0, 12, 2))

    ret['is_up'] = True if data_dict.get('Link Status', '').lower() == 'up' else False
    ret['is_enabled'] = True if data_dict.get('Port Enabled', '').lower() == 'yes' else False
    ret['description'] = data_dict.get('Name', '')
    ret['last_flapped'] = 0.0  # need to clarify how to get this value
    ret['speed'] = 0  # need to clarify how to get this value
    ret['mtu'] = 0  # need to clarify how to get this value
    ret['mac_address'] = mac

    return ret
