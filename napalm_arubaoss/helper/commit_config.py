"""Backups and commit the configuration, and handles commit confirm."""

import logging

from napalm.base.exceptions import CommitError

from napalm_arubaoss.helper.utils import backup_config, commit_candidate
from napalm_arubaoss.helper.get_config import get_config
from napalm_arubaoss.helper.load_replace_candidate import load_replace_candidate
from napalm_arubaoss.helper.has_pending_commit import has_pending_commit

logger = logging.getLogger("arubaoss.helper.commit_config")


def commit_config(self, message="", revert_in=None):
    """
    Backups and commit the configuration, and handles commit confirm.

    :param self: object from class
    :param message: Optional - configuration session commit message
    :type message: str
    :param revert_in: Optional - number of seconds before the configuration
    will be rolled back using a commit confirm mechanism.
    :type revert_in: int|None
    """
    if message:
        msg = "\"message\" support has not been added " \
              "for this getter on this platform."
        raise NotImplementedError(msg)

    if not revert_in:
        revert_in = 0

    if not type(revert_in) == int:
        err_msg = "Invalid \"revert_in\" value, "\
                  "commit confirn cannot be carried out"
        logger.error(err_msg)
        raise TypeError(err_msg)

    if has_pending_commit(self=self):
        raise CommitError("Pending commit confirm already in process!")

    backup_config(self=self)

    logger.debug('Confirm rollback time is {}'.format(str(revert_in)))
    if revert_in > 0:
        candidate = get_config(
            self=self,
            retrieve='candidate'
        )['candidate']
        candidate = candidate[:-2]  # remove unneeded chars

        candidate_confirm = (
            f"{candidate}"
            f"job ROLLBACK delay {str(revert_in)} "
            "\"cfg-restore flash backup_running\"\n"
        )
        load_replace_candidate(self=self, config=candidate_confirm)

    commit_candidate(self=self, config="REST_Payload_Backup")
