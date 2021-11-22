"""Merge candidate configuration with the running one."""

from napalm.base.exceptions import MergeConfigException
import logging

from napalm_arubaoss.helper.utils import read_candidate, config_batch, backup_config

logger = logging.getLogger("arubaoss.helper.load_merge_candidate")


def load_merge_candidate(self, filename=None, config=None):
    """
    Merge candidate configuration with the running one.

    Imperative config change:
     Merge new config with existing one. There's no config validation
     nor atomic commit!. Only configuration commands are supported,
     "configure terminal" is not required. Use with caution.

    :param self: object from class
    :param filename:
    :param config:
    :return:
    """
    if filename:
        config = read_candidate(candidate=filename)

    if config is not None:
        if isinstance(config, str):
            config = config.split("\n")
        if not config_batch(self=self, cmd_list=config):
            raise MergeConfigException("Configuration merge failed")

    # mimic load_replace_candidate behaviour, by making sure candidate
    # config exactly matches our merged configuration
    backup_config(self=self, destination="REST_Payload_Backup")
