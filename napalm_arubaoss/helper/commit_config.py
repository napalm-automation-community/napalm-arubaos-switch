"""Backups and commit the configuration, and handles commit confirm."""

import logging

from napalm_arubaoss.helper.utils import backup_config, commit_candidate
from napalm_arubaoss.helper.get_config import get_config
from napalm_arubaoss.helper.load_replace_candidate import load_replace_candidate

logger = logging.getLogger("arubaoss.helper.commit_config")


def commit_config(connection, confirm=0):
    """Backups and commit the configuration, and handles commit confirm."""
    backup_config(connection)
    logger.debug("Confirm rollback time is {}".format(str(confirm)))
    if confirm > 0:
        candidate = get_config(connection=connection, retrieve="candidate")[
            "candidate"
        ][:-2]
        candidate_confirm = (
            candidate
            + 'job ROLLBACK delay {} \
            "cfg-restore flash backup_running"\n'.format(
                str(confirm)
            )
        )
        load_replace_candidate(connection=connection, config=candidate_confirm)
    commit_candidate(connection=connection, config="REST_Payload_Backup")
