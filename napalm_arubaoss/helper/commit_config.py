"""Backups and commit the configuration, and handles commit confirm."""

import logging

from napalm_arubaoss.helper.utils import backup_config, commit_candidate
from napalm_arubaoss.helper.get_config import get_config
from napalm_arubaoss.helper.load_replace_candidate import load_replace_candidate

logger = logging.getLogger("arubaoss.helper.commit_config")


def commit_config(self, message=""):
    """Backups and commit the configuration, and handles commit confirm."""

    if message:
        msg = "\"message\" support has not been added " \
              "for this getter on this platform."
        raise NotImplementedError(msg)

    backup_config(self.connection)
    commit_candidate(self=self, config="REST_Payload_Backup")
