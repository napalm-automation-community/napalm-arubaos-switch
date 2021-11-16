"""Confirm the changes requested via commit_config when `type(revert_in)=int`."""

import logging

from napalm_arubaoss.helper.get_config import get_config


logger = logging.getLogger('arubaoss.helper.has_pending_commit')


def has_pending_commit(self):
    """
    Boolean indicates if a commit_config that needs confirmed is in process.

    :param self: object from class
    :return Boolean
    """
    running = get_config(self=self, retrieve='running')['running'][:-2]

    for line in running.split("\n"):
        if line.find("ROLLBACK") > 0:
            return True

    return False
