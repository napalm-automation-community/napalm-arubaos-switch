"""Replace running config with the candidate."""

from napalm.base.exceptions import ReplaceConfigException
import logging

from napalm_arubaoss.helper.utils import str_to_b64, read_candidate

logger = logging.getLogger("arubaoss.helper.load_replace_candidate")


def load_replace_candidate(self, filename=None, config=None):
    """
    Replace running config with the candidate.

    Implentation of napalm module load_replace_candidate()
    ArubaOS-Switch supports payload_type options:
        - "RPT_PATCH_FILE" -> not implemented
        - "RPT_BACKUP_FILE" -> Implemented

    Note: the maximum content_length = 16072,
    "HTTP/1.1 413 Request Entity Too Large" is returned above that!!!

    :param self: object from class
    :param filename:
    :param config:
    :return:
    """
    url = self.connection.config["api_url"] + "system/config/payload"
    payload = {"payload_type": "RPT_BACKUP_FILE"}
    if filename is not None:
        config = read_candidate(candidate=filename)

    if config is not None:
        payload["config_base64_encoded"] = str_to_b64(config)
        load = self.connection.post(url, json=payload)
        if load.status_code != 200:
            raise ReplaceConfigException(
                f"Load configuration failed - Reason: {load.text}"
            )
