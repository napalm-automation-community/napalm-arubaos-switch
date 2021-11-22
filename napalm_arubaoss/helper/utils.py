"""Implement all utilities used by other modules."""

import base64
import logging
from time import sleep
from itertools import zip_longest
from napalm.base.exceptions import CommandTimeoutException

logger = logging.getLogger("arubaoss.helper.utils")


def read_candidate(candidate):
    """
    Open the candidate config.

    :param candidate:
    :return:
    """
    with open(candidate) as candidate_config:
        return "".join(candidate_config.readlines())


def str_to_b64(spayload):
    """
    Convert from str to b64 for aoss API.

    :param spayload:
    :return:
    """
    payload_b64 = base64.b64encode(spayload.encode())

    return payload_b64.decode("utf-8")


def config_batch(self, cmd_list):
    """
    Load a batch of configuration commands into the running-config.

    :param self: object from class
    :param cmd_list:
    :return:
    """
    url = self.connection.config["api_url"] + "cli_batch"
    data = {"cli_batch_base64_encoded": str_to_b64("\n".join(cmd_list))}
    batch_run = self.connection.post(url, json=data)

    if not batch_run.status_code == 202:
        logger.debug("Failed to paste commands")

        return False

    check_status = self.connection.get(url + "/status")
    if check_status.status_code == 200:
        for cmd_status in check_status.json()["cmd_exec_logs"]:
            if not cmd_status["status"] == "CCS_SUCCESS":
                logger.warning(
                    "command failed to execute with error {}".format(
                        cmd_status["result"]
                    )
                )
                return False
        return True


def backup_config(self, config="running", destination="backup"):
    """
    Backup config.

    Supported configs
    API:
        - "CT_RUNNING_CONFIG",
        - "CT_STARTUP_CONFIG"

    :param self: object from class
    :param config:
    :param destination:
    :return:
    """
    url = self.connection.config["api_url"] + "system/config/cfg_backup_files"
    payload = {}
    dest_map = {
        "backup": "backup_{}".format(config),
        "REST_Payload_Backup": "REST_Payload_Backup",
    }
    conf_map = {
        "running": "CT_RUNNING_CONFIG",
        "startup": "CT_STARTUP_CONFIG"
    }
    payload["file_name"] = dest_map.get(destination)
    payload["config_type"] = conf_map.get(config, False)

    if not payload["config_type"]:
        "unsupported argument; raise error"
        return False

    cmd_post = self.connection.post(url, json=payload)
    if not cmd_post.ok:
        "raise error"
        pass
    else:
        return cmd_post.json()


def transaction_status(self, url):
    """
    Wait for the requested transaction to finish within the specified timeout.

    :param self: object from class
    :param url:
    :return:
    """
    status = "CRS_IN_PROGRESS"
    elapsed = 0
    while status == "CRS_IN_PROGRESS" and elapsed < self.connection.timeout:
        call = self.connection.get(url)
        if call.status_code in range(200, 300):
            status = call.json()
            return status
        elapsed += 1
        sleep(1)
    if elapsed == (int(self.connection.timeout) - 1) and status == "CRS_IN_PROGRESS":
        raise CommandTimeoutException("Transaction timed out")


def commit_candidate(self, config):
    """
    Commit the candidate configuration.

    :param self: object from class
    :param config:
    :return:
    """
    url = self.connection.config["api_url"] + "system/config/cfg_restore"
    data = {"server_type": "ST_FLASH", "file_name": config, "is_oobm": False}
    cmd_post = self.connection.post(url, json=data)

    if not cmd_post.json()["failure_reason"]:
        check_url = url + "/status"

        return transaction_status(self=self, url=check_url)


def mac_reformat(mac):
    """
    Reformat the MAC addresses to standard notation.

    :param mac:
    :return:
    """
    t = iter(mac.replace("-", ""))

    return ":".join(a + b for a, b in zip_longest(t, t, fillvalue=""))
