"""Merge candidate configuration with the running one."""

from napalm.base.exceptions import MergeConfigException
import logging

from napalm_arubaoss.helper.utils import read_candidate, config_batch, backup_config

logger = logging.getLogger('arubaoss.helper.load_merge_candidate')


def load_merge_candidate(connection, filename=None, config=None):
    """Merge candidate configuration with the running one."""
    """
    Imperative config change:
     Merge new config with existing one. There's no config validation
     nor atomic commit!. Only configuration commands are supported,
     "configure terminal" is not required. Use with caution.

    """
    if filename:
        config = read_candidate(connection=connection, candidate=filename)

    if config is not None:
        if isinstance(config, str):
            config = config.split('\n')
        if not config_batch(connection=connection, cmd_list=config):
            raise MergeConfigException("Configuration merge failed")

    # mimic load_replace_candidate behaviour, by making sure candidate
    # config exactly matches our merged configuration
    backup_config(connection=connection, destination='REST_Payload_Backup')
