"""Get NTP peer statistics."""

import logging

logger = logging.getLogger("arubaoss.helper.get_ntp_stats")


def get_ntp_stats(self):
    """
    Get NTP peer statistics.

    :param self: object from class
    :return:
    """
    out = []
    base_url = self.connection.config["api_url"]
    ret = self.connection.get(
        f"{base_url}monitoring/ntp/servers"
    )

    ret_json = ret.json() if hasattr(ret, "json") else {}

    ntp_ips = [
        address.get("Server address")
        for address in ret_json.get("NTP_Server_Address_Information", [])
    ]

    for association in ntp_ips:
        url = f"{base_url}monitoring/ntp/associations/detail/{association}"

        resp = self.connection.get(url)
        if resp.status_code == 200:
            data = resp.json() if hasattr(resp, "json") else {}

            ntp_entry = _create_ntp_entry(data)

            if ntp_entry:
                out.append(ntp_entry)

    if not ntp_ips:
        # assumes no IPs have been configured but a name
        url = f"{base_url}monitoring/ntp/associations/detail"
        resp = self.connection.get(url)

        if resp.status_code == 200:
            data = resp.json() if hasattr(resp, "json") else {}

            ntp_entry = _create_ntp_entry(data)

            if ntp_entry:
                out.append(ntp_entry)

    return out


def _create_ntp_entry(data):
    if not data:
        return None

    ntp_entry = {
        "remote": data.get("IP Address", ""),
        "referenceid": data.get("Reference ID", ""),
        "stratum": int(data.get("Stratum", 0)),
        "type": data.get("Peer Mode", ""),
        "when": data.get("Origin Time", ""),
        "hostpoll": int(data.get("Peer Poll Intvl", 0)),
        "reachability": int(data.get("Reach", 0)),
        "delay": float(data.get("Root Delay", "").split(" ")[0]),
        "offset": float(data.get("Offset", "").split(" ")[0]),
        "jitter": float(data.get("Root Dispersion", "").split(" ")[0]),
    }

    if data.get("Status").find("Master") == -1:
        ntp_entry["synchronized"] = False
    else:
        ntp_entry["synchronized"] = True

    return ntp_entry
