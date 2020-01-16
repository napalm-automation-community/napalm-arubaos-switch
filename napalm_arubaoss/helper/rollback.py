"""Rollback configuration."""

import logging

from napalm_arubaoss.helper.utils import commit_candidate
from napalm_arubaoss.helper.compare_config import compare_config

logger = logging.getLogger('arubaoss.helper.rollback')


def rollback():
    """Rollback configuration."""
    diff = compare_config()
    if diff and isinstance(diff, dict):
        if not (
                len(diff.get('diff_add_list')) and
                len(diff.get('diff_remove_list'))
        ):
            commit_candidate(config='backup_running')

            return True
        else:
            return False
