"""Shared fixtures for the Modbus interface test suite. These run without a platform, a proxy, or a device."""
import json

from pathlib import Path
from unittest import mock

import pytest

from gevent.event import AsyncResult

from volttron.driver.base.config import RemoteConfig
from volttron.driver.interfaces.modbus.modbus import Modbus, ModbusPointConfig

TESTS_DIR = Path(__file__).parent
CATALYST_CSV = TESTS_DIR.parent / 'catalyst371.csv'


class FakePPM:
    """Stands in for GeventProtocolProxyManager: records every payload sent and replays queued replies."""

    def __init__(self):
        self.sent: list[tuple[str, dict]] = []
        self.replies: list = []
        self.peer = object()
        self.started = 0

    def queue(self, *replies):
        self.replies.extend(replies)

    def start(self):
        self.started += 1

    def select_loop(self):
        pass

    def get_proxy(self, key, **kwargs):
        self.proxy_key, self.proxy_kwargs = key, kwargs
        return self.peer

    def wait_peer_registered(self, peer, timeout, func=None, *args, **kwargs):
        self.registration_wait = timeout
        if func:
            func(*args, **kwargs)

    def send(self, peer, message):
        self.sent.append((message.method_name, json.loads(message.payload.decode('utf8'))))
        reply = self.replies.pop(0) if self.replies else serialized({})
        if isinstance(reply, (bytes, bytearray)):
            result = AsyncResult()
            result.set(reply)
            return result
        return reply       # e.g. False, to simulate an unsendable request

    def payloads(self, method_name=None):
        return [p for m, p in self.sent if method_name is None or m == method_name]


def serialized(result, error=None):
    """A reply as the proxy's serializer would produce it."""
    return json.dumps({'result': result, 'error': error if error is not None else {}}).encode('utf8')


def point(name, address, data_type='>f', writable=False, **extra):
    return ModbusPointConfig(volttron_point_name=name, address=address, data_type=data_type, writable=writable,
                             units=extra.pop('units', 'F'), **extra)


@pytest.fixture
def ppm():
    return FakePPM()


@pytest.fixture
def make_interface(ppm):
    """Build a real Modbus interface whose proxy manager is the FakePPM."""
    def build(points=(), base_topic='campus/building/rtu', **remote):
        remote = {'driver_type': 'modbus', 'device_address': '10.0.0.4', **remote}
        Modbus.default_config = {}
        with mock.patch('volttron.driver.interfaces.modbus.modbus.GeventProtocolProxyManager') as manager_class:
            manager_class.get_manager.return_value = ppm
            interface = Modbus(RemoteConfig(**remote), driver_agent=mock.Mock())
        for p in points:
            interface.insert_register(interface.create_register(p), base_topic)
        return interface
    return build


@pytest.fixture
def interface(make_interface):
    """Two floats at 1001 and 1003, a pad over 1005-1009, a uint16 at 1010, and two coils."""
    iface = make_interface([
        point('ReturnAirCO2', 1001),
        point('CO2Stpt', 1003, writable=True, default_value='1000'),
        point('gap', 1005, 'pad[5]', table='input'),
        point('Mode', 1010, 'uint16', writable=True),
        point('FanStatus', 3, 'bool'),
        point('FanCmd', 5, 'bool', writable=True),
    ])
    iface.proxy_peer = iface.ppm.peer
    return iface


TOPIC = 'campus/building/rtu/{}'.format
