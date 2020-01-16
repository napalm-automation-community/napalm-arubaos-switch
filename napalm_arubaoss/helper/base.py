from requests_futures.sessions import FuturesSession
from requests.models import Response
from concurrent.futures import as_completed
from json import JSONDecodeError
import base64
import logging

from napalm.base.exceptions import ConnectAuthError


logger = logging.getLogger('arubaoss.helper.base')


class Connection:
    _apisession = FuturesSession()
    config = {'api_url': ''}

    def __init__(self):
        self.hostname = ''
        self.username = ''
        self.password = ''
        self.timeout = 10
        self.api = 'v6'
        self.proto = 'https'

        self.cli_output = {}

    def login(
            self,
            hostname,
            username='',
            password='',
            timeout=10,
            optional_args=None
    ):
        logger.debug('logging in')
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.api = optional_args.get('api', 'v6')

        if not optional_args:
            optional_args = {}

        self.proto = 'https' if optional_args.get("ssl", True) else 'http'

        self.config['api_url'] = '{}://{}/rest/{}/'.format(
            self.proto,
            self.hostname,
            self.api
        )

        url = self.config['api_url'] + 'login-sessions'

        self._apisession.verify = optional_args.get("ssl_verify", True)
        self._apisession.headers = {'Content-Type': 'application/json'}
        # bug #4 - random delay while re-using TCP connection - workaround:
        self._apisession.keep_alive = optional_args.get("keepalive", True)

        params = {
            'userName': self.username,
            'password': self.password
        }

        rest_login = self.post(
            url,
            json=params,
            timeout=self.timeout
        )

        if not rest_login.status_code == 201:
            raise ConnectAuthError("Login failed")

        session = rest_login.json()
        self._apisession.headers['cookie'] = session['cookie']

    def logout(self):
        """Close device connection and delete sessioncookie."""
        url = self.config['api_url'] + 'login-sessions'

        rest_logout = self.delete(url)
        self._apisession.headers['cookie'] = ''

        if not rest_logout.status_code == 204:
            logger.debug("Logout Failed")
        else:
            return "logout ok"

    def get(self, *args, **kwargs) -> Response:
        """
        Call a single command (Helper-Function).

        :param args:
        :param kwargs:
        :return:
        """
        ret = self._apisession.get(*args, **kwargs)

        return ret.result()

    def post(self, *args, **kwargs) -> Response:
        """
        Call a single command (Helper-Function).

        :param args:
        :param kwargs:
        :return:
        """
        ret = self._apisession.post(*args, **kwargs)

        return ret.result()

    def put(self, *args, **kwargs) -> Response:
        """
        Call a single command (Helper-Function).

        :param args:
        :param kwargs:
        :return:
        """
        ret = self._apisession.put(*args, **kwargs)

        return ret.result()

    def delete(self, *args, **kwargs) -> Response:
        """
        Call a single command (Helper-Function).

        :param args:
        :param kwargs:
        :return:
        """
        ret = self._apisession.delete(*args, **kwargs)

        return ret.result()

    def cli(self, commands):
        """Run CLI commands through the REST API."""
        self.cli_output = {}

        url = self.config['api_url'] + 'cli'

        if not isinstance(commands, list):
            self.cli_output['error'] = 'Provide a list of commands'
            return self.cli_output

        async_calls = (
            self._apisession.post(
                url=url,
                json={'cmd': command},
                hooks={
                    'response': self._callback(
                        output=self.cli_output,
                        command=command
                    )
                }
            ) for command in commands
        )

        [call.result() for call in as_completed(async_calls)]

        return self.cli_output

    def _callback(self, *args, **kwargs):
        """
        Return Callback for async calls.

        ArubaOSS.cli uses it.

        :param args:
        :param kwargs:
        :return: callback function
        """
        def callback(call, *cargs, **ckwargs):
            self.cli_output = kwargs.get('output')
            passed_cmd = kwargs.get('command')
            try:
                json_ret = call.json()
            except JSONDecodeError:
                json_ret = {}

            cmd = json_ret.get('cmd')
            result_base64 = json_ret.get('result_base64_encoded', '')

            if not cmd == passed_cmd:
                self.cli_output[passed_cmd] = 'cmd not found in output'
                return

            if not result_base64:
                self.cli_output[passed_cmd] = 'no result found in output'
                return

            result = base64.b64decode(result_base64).decode('utf-8')
            self.cli_output[passed_cmd] = result

        return callback

    def run_cmd(self, cmd):
        ret = self.cli([cmd])
        return ret[cmd]
