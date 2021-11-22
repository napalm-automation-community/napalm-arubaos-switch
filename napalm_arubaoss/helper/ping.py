"""Execute ping on the device and returns a dictionary with the result."""

import logging

logger = logging.getLogger("arubaoss.helper.ping")


def ping(self, destination, timeout=2):
    """
    Execute ping on the device and returns a dictionary with the result.

    :param self: object from class
    :param destination: needed argument
    :param timeout: not implemented as not available from device
    :return: returns a dictionary containing the hops and probes
    """
    url = self.connection.config["api_url"] + "ping"
    data = {
        "destination": {"ip_address": {"version": "IAV_IP_V4", "octets": destination}},
        "timeout_in_seconds": timeout,
    }
    data_post = self.connection.post(url, json=data)

    if not data_post.status_code == 200:
        return {"error": "unknown host {}".format(destination)}

    return_post = data_post.json() if hasattr(data_post, "json") else {}
    result_post = return_post.get("result", "")
    rtt = return_post.get("rtt_in_milliseconds", 0)
    rtt_float = float(rtt)

    if "PR_OK" in result_post:
        result = {
            "success": {
                "probes_sent": 1,
                "packet_loss": 0,
                "rtt_min": rtt_float,
                "rtt_max": rtt_float,
                "rtt_avg": rtt_float,
                "rtt_stddev": 0.0,
                "results": [
                    {
                        "ip_address": destination,
                        "rtt": rtt_float
                    }
                ]
            }
        }
        return result
