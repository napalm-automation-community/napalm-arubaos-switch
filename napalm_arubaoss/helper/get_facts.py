"""Get general device information."""

import logging

logger = logging.getLogger("arubaoss.helper.get_facts")


def get_facts(self):
    """
    Get general device information.

    :param self: object from class
    :return:
    """
    url = "{base_url}{endpoint}"

    system_status_url = url.format(
        base_url=self.connection.config["api_url"],
        endpoint="system/status"
    )
    switch_status_url = url.format(
        base_url=self.connection.config["api_url"],
        endpoint="system/status/switch"
    )
    dns_url = url.format(
        base_url=self.connection.config["api_url"],
        endpoint="dns"
    )

    out = {
        "uptime": -1,
        "vendor": "HPE Aruba",
        "model": "",
        "hostname": "",
        "fqdn": "",
        "os_version": "",
        "serial_number": "",
        "interface_list": [],

    }

    call = self.connection.get(system_status_url)

    # If it's a Stack, use `/system/status/global_info`
    if call.status_code == 404:
        system_status_url = url.format(
            base_url=self.connection.config["api_url"],
            endpoint="system/status/global_info"
        )
        call = self.connection.get(system_status_url)

    if call.ok:
        rest_out = call.json()
        out["hostname"] = rest_out.get("name", "")
        out["os_version"] = rest_out.get("firmware_version", "")
        out["serial_number"] = rest_out.get("serial_number", "")
        out["model"] = rest_out.get("product_model", "")

        # get domain name to generate the FQDN
        call = self.connection.get(dns_url)
        if call.ok:
            rest_out = call.json()
            # return "{{hostname}}." if no domain is configured
            domain_names = rest_out.get("dns_domain_names")
            domain = ".{}".format(domain_names[0]) if domain_names else "."
            out["fqdn"] = "{hostname}{domain}".format(
                hostname=out["hostname"],
                domain=domain
            )

    # Get interface list
    call = self.connection.get(switch_status_url)
    if call.ok:
        rest_out = call.json()
        if rest_out.get("switch_type", "ST_STANDALONE") == "ST_STACKED":
            serial_url = url.format(
                base_url=self.connection.config["api_url"],
                endpoint="system/status/members/1"
            )
            call = self.connection.get(serial_url)

            if call.ok:
                out["serial_number"] = call.json().get("serial_number", "")
                out["model"] = call.json().get("product_model", "")

        for blade in rest_out.get("blades", []):
            for ports in blade.get("data_ports", []):
                out["interface_list"].append(
                    ports.get("port_name", "")
                )

    return out
