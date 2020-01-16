import logging
from napalm.base.exceptions import CommandErrorException

from napalm_arubaoss.helper.base import Connection

logger = logging.getLogger('arubaoss.helper.compare_config')

connection = Connection()


def compare_config():
    """Compare the running config with the candidate one."""
    url = connection.config['api_url'] + 'system/config/cfg_restore/latest_diff'
    check_url = url + '/status'
    data = {
        "server_type": "ST_FLASH",
        "file_name": "REST_Payload_Backup",
        "is_oobm": False
    }
    # trigger configuration comparison
    diff = connection.post(url, json=data)

    if not diff.ok:
        raise CommandErrorException("diff generation failed, raise status")

    diff_output = connection.get(check_url)

    if not diff_output.status_code == 200:
        raise CommandErrorException("diff generation failed, raise status")

    if not diff_output.json()['diff_add_list'] and \
            not diff_output.json()['diff_remove_list']:
        # return empty string to signal the candidate
        # and running configs are the same

        return ''
    else:
        return diff_output.json()