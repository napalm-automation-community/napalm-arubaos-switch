"""Backups and commit the configuration, and handles commit confirm."""

import logging

from time import sleep

from napalm.base.exceptions import CommandErrorException

logger = logging.getLogger("arubaoss.helper.compare_config")


def compare_config(self):
    """
    Compare the running config with the candidate one.

    :param self: object from class
    :return:
    """
    url = self.connection.config["api_url"] + "system/config/cfg_restore/latest_diff"
    check_url = url + "/status"
    data = {
        "server_type": "ST_FLASH",
        "file_name": "REST_Payload_Backup",
        "is_oobm": False,
    }
    # trigger configuration comparison
    diff = self.connection.post(url, json=data)

    if not diff.ok:
        raise CommandErrorException("diff generation failed, raise status")

    for loop_round in range(1, 6):
        # wait a second to give the device time to process
        logger.debug(f"loop round \"{loop_round}\"")
        sleep(1)

        diff_output = self.connection.get(check_url)

        if not diff_output.status_code == 200:
            raise CommandErrorException("diff generation failed, raise status")

        if (
            not diff_output.json()["diff_add_list"]
            and not diff_output.json()["diff_remove_list"]
        ):
            if loop_round == 5:
                # return empty string to signal the candidate
                # and running configs are the same
                return ""
            continue
        else:
            return diff_output.json()
