"""Get configuration stored on the device."""

import logging

logger = logging.getLogger("arubaoss.helper.get_config")


def get_config(self, retrieve="all"):
    """Get configuration stored on the device."""
    out = {"startup": "", "candidate": "", "running": ""}

    cmd_mapping = {
        "display saved-configuration": "startup",
        "show config REST_Payload_Backup": "candidate",
        "show running-config": "running",
    }
    cmd_mapping = (
        {key: value for key, value in cmd_mapping.items() if retrieve == value}
        if not retrieve == "all"
        else cmd_mapping
    )

    outputs = self.connection.cli([cmd for cmd, config in cmd_mapping.items()])

    for okey, ovalue in outputs.items():
        out[cmd_mapping[okey]] = ovalue

    return out
