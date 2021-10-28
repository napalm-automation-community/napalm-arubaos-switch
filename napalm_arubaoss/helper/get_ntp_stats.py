"""Get NTP peer statistics."""

import logging

from napalm_arubaoss.helper.get_ntp_servers import get_ntp_servers

logger = logging.getLogger("arubaoss.helper.get_ntp_stats")


def get_ntp_stats(connection):
    """Get NTP peer statistics."""
    out = []
    associations = get_ntp_servers()

    for association in associations.keys():
        url = "{api_url}monitoring/ntp/associations/detail/{association}".format(
            api_url=connection.config["api_url"], association=association
        )

        resp = connection.get(url)
        if resp.status_code == 200:
            ntp_entry = {
                "remote": resp.json()["IP Address"],
                "referenceid": resp.json()["Reference ID"],
                "stratum": int(resp.json()["Stratum"]),
                "type": resp.json()["Peer Mode"],
                "when": resp.json()["Origin Time"],
                "hostpoll": int(resp.json()["Peer Poll Intvl"]),
                "reachability": int(resp.json()["Reach"]),
                "delay": float(resp.json()["Root Delay"].split(" ")[0]),
                "offset": float(resp.json()["Offset"].split(" ")[0]),
                "jitter": float(resp.json()["Root Dispersion"].split(" ")[0]),
            }

            if resp.json()["Status"].find("Master") == -1:
                ntp_entry["synchronized"] = False
            else:
                ntp_entry["synchronized"] = True

            out.append(ntp_entry)

    return out
