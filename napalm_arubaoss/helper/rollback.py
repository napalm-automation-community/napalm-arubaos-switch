"""Rollback configuration."""

import logging

from napalm_arubaoss.helper.utils import commit_candidate
from napalm_arubaoss.helper.compare_config import compare_config

logger = logging.getLogger("arubaoss.helper.rollback")


def rollback(self):
    """
    Rollback configuration.

    :param self: object from class
    :return:
    """
    diff = compare_config(self=self)
    if diff and isinstance(diff, dict):
        if not (len(diff.get("diff_add_list")) and len(diff.get("diff_remove_list"))):
            commit_candidate(self=self, config="backup_running")

            return True
        else:
            return False
