"""
Confirm the changes requested via commit_config when `type(revert_in)=int`.
"""

import logging

from napalm_arubaoss.helper.base import Connection
from napalm_arubaoss.helper.commit_config import commit_config
from napalm_arubaoss.helper.has_pending_commit import has_pending_commit
from napalm_arubaoss.helper.load_merge_candidate import load_merge_candidate

logger = logging.getLogger('arubaoss.helper.confirm_commit')

connection = Connection()


def confirm_commit():
    """
    Confirm the changes requested via commit_config when `type(revert_in)=int`.
    """
    if has_pending_commit():
        load_merge_candidate(config="no job ROLLBACK")
        ret = commit_config()

        return ret
