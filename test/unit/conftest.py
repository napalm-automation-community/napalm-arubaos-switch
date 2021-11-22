"""Test fixtures."""

from re import search

import pytest
from napalm.base.test import conftest as parent_conftest

from napalm.base.test.double import BaseTestDouble

from napalm_arubaoss import ArubaOS


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = ArubaOS.ArubaOSS
    request.cls.patched_driver = PatchedArubaOSDriver
    request.cls.vendor = 'napalm_arubaoss'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedArubaOSDriver(ArubaOS.ArubaOSS):
    """Patched ArubaOS Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['connection']
        self.connection = FakeArubaOSDevice()
        self.platform = "arubaos"

    def disconnect(self):
        pass

    def is_alive(self):
        return {
            'is_alive': True  # In testing everything works..
        }

    def open(self):
        pass


class FakeArubaOSDevice(BaseTestDouble):
    """ArubaOS device test double."""
    def __init__(self):
        super().__init__()
        self.config = {'api_url': ''}

    def get(self, url: str):
        full_path = self.find_file('facts.json')
        facts = self.read_json_file(full_path)

        facts = facts.get(url)
        resp = Response(
            facts.get('data', {}),
            status=facts.get('status', 204),
            ok=facts.get('ok', True)
        )
        return resp

    def post(self, url: str, json=None):
        full_path = self.find_file('facts.json')
        facts = self.read_json_file(full_path)

        facts = facts.get(url)
        resp = Response(
            facts.get('data', {}),
            status=facts.get('status', 204),
            ok=facts.get('ok', True)
        )
        return resp

    def cli(self, commands):
        full_path = self.find_file('cli_mapping.json')
        cli_mapping = self.read_json_file(full_path)

        fake_return = {}

        for cmd in commands:
            cli_match = cli_mapping.get(cmd)
            if not cli_match:
                return
            fake_return[cmd] = cli_match

        return fake_return

    def run_cmd(self, cmd):
        return self.cli([cmd])[cmd]

    def show(self, command, raw_text=False):
        """Fake show."""
        filename = '{}.json'.format(command.replace(' ', '_'))
        full_path = self.find_file(filename)

        if raw_text:
            result = self.read_txt_file(full_path)
        else:
            result = self.read_json_file(full_path)

        return result

    def login(self):
        pass

    def logout(self):
        pass

    def config_list(self, command):
        """Fake config_list."""
        pass


class Response:
    def __init__(self, data, status=204, ok=True):
        self.status_code = status
        self.ok = ok
        self.data = data

    def json(self):
        return self.data
