"""Confirm the changes requested via commit_config when `type(revert_in)=int`."""

import logging

from napalm_arubaoss.helper.commit_config import commit_config
from napalm_arubaoss.helper.has_pending_commit import has_pending_commit
from napalm_arubaoss.helper.load_merge_candidate import load_merge_candidate

logger = logging.getLogger('arubaoss.helper.confirm_commit')


def confirm_commit(self):
    """
    Confirm the changes requested via commit_config when `type(revert_in)=int`.

    :param self: object from class
    :return:
    """
    if has_pending_commit(self=self):
        load_merge_candidate(self=self, config="no job ROLLBACK")
        ret = commit_config(self=self)

        return ret
