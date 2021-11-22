"""Execute traceroute on the device and returns a dictionary with the result."""

import socket
import logging

logger = logging.getLogger("arubaoss.helper.traceroute")


def traceroute(self, destination):
    """
    Execute traceroute on the device and returns a dictionary with the result.

    :param self: object from class
    :param destination: needed argument
    :return: returns a dictionary containing the hops and probes
    """
    url = self.connection.config["api_url"] + "trace-route"
    data = {
        "destination": {"ip_address": {"version": "IAV_IP_V4", "octets": destination}}
    }
    data_post = self.connection.post(url, json=data)

    if not data_post.status_code == 200:
        return {"error": "unknown host {}".format(destination)}

    ret = {"success": {}}
    ttl_data = data_post.json().get("ttl_data", [])

    for hop_count in range(len(ttl_data)):
        ret["success"][hop_count + 1] = {"probes": {}}
        ttl_probe_data = ttl_data[hop_count].get("ttl_probe_data", [])
        for probe_count in range(len(ttl_probe_data)):
            try:
                hostname, _, _ = socket.gethostbyaddr(
                    ttl_probe_data[probe_count]
                    .get("gateway", {})
                    .get("ip_address", {})
                    .get("octets", "")
                )
            except socket.herror:  # fetch if nothing can be found
                hostname = ""

            probe = {
                "rtt": float(ttl_probe_data[probe_count]["probe_time_in_millis"]),
                "ip_address": ttl_probe_data[probe_count]
                .get("gateway", {})
                .get("ip_address", {})
                .get("octets", ""),
                "host_name": hostname,
            }

            ret["success"][hop_count + 1]["probes"][probe_count + 1] = probe
            del probe

    return ret
