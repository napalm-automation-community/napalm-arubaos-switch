"""Get the environment variables of the switch/es"""

import logging

from napalm.base.helpers import textfsm_extractor

logger = logging.getLogger("arubaoss.helper.get_environment")


def get_environment(self):
    """
    Get device's Environment table.

    :param self: object from class
    :return:
    """

    out = {
        "fans": {},
        "temperature": {},
        "power": {},
        "cpu": {},
        "memory": {}
    }

    raw_system = self.connection.run_cmd("show system")
    system_list = textfsm_extractor(self, "show_system", raw_system)

    memtotal = 0
    memfree = 0

    for switch in system_list:
        member = switch.pop("member")
        if member == "":
            member = 0
        else:
            member = "Member " + member

        out["cpu"][member] = {
            "%usage": float(switch.pop("cpu"))
        }

        memtotal += int(switch.pop("memtotal").replace(',', ''))
        memfree += int(switch.pop("memfree").replace(',', ''))

    out["memory"] = {
        "available_ram": int(memtotal),
        "used_ram": int(memfree)
    }

    raw_system_fans = self.connection.run_cmd("show system fans")
    system_fans_list = textfsm_extractor(self, "show_system_fans", raw_system_fans)
    for fan in system_fans_list:
        member = fan.pop("member")
        if member != "":
            member = "Member " + member + " "

        out["fans"][member + fan.pop('location') + " " + fan.pop('num')] = {
            "status": True if fan.pop('state') == "Fan OK" else False
        }

    raw_system_temperature = self.connection.run_cmd("show system temperature")
    system_temperature_list = textfsm_extractor(self, "show_system_temperature", raw_system_temperature)
    for temp in system_temperature_list:
        member = temp.pop("member")
        if member != "":
            member = "Member " + member + " "

        overtemp = True if temp.pop('overtemp') == "YES" else False

        out["temperature"][member + temp.pop('sensor')] = {
            "temperature": float(temp.pop('temperature')),
            "is_alert": overtemp,
            "is_critical": overtemp
        }

    raw_system_power = self.connection.run_cmd("show system power-supply")
    system_power_list = textfsm_extractor(self, "show_system_power-supply", raw_system_power)
    for power in system_power_list:
        member = power.pop("member")
        if member != "":
            member = "Member " + member + " "

        out["power"][member + power.pop('ps')] = {
            "status": True if power.pop('state') == "Powered" else False,
            "capacity": float(power.pop('max')),
            "output": float(power.pop('wattage'))
        }

    return out
