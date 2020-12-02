"""Backups and commit the configuration, and handles commit confirm."""

import logging

from napalm.base.exceptions import CommitError

from napalm_arubaoss.helper.base import Connection
from napalm_arubaoss.helper.get_config import get_config
from napalm_arubaoss.helper.has_pending_commit import has_pending_commit
from napalm_arubaoss.helper.load_replace_candidate import \
    load_replace_candidate
from napalm_arubaoss.helper.utils import (
    backup_config,
    commit_candidate
)

logger = logging.getLogger('arubaoss.helper.commit_config')

connection = Connection()


def commit_config(revert_in=0):
    """
    Backups and commit the configuration, and handles commit confirm.

    :param message: Optional - configuration session commit message
    :type message: str
    :param revert_in: Optional - number of seconds before the configuration
    will be rolled back using a commit confirm mechanism.
    :type revert_in: int|None
    """
    backup_config()
    logger.debug('Confirm rollback time is {}'.format(str(revert_in)))
    if revert_in is not None:

        if has_pending_commit():
            raise CommitError("Pending commit confirm already in process!")

        if type(revert_in) == int:
            candidate = get_config(retrieve='candidate')['candidate'][:-2]
            candidate_confirm = candidate + 'job ROLLBACK delay {} \
                "cfg-restore flash backup_running"\n'.format(str(revert_in))
            load_replace_candidate(config=candidate_confirm)
        else:
            logger.error("Invalid \"rever_in\" value,\
                commit confirn cannot be carried out")

    commit_candidate(config='REST_Payload_Backup')
