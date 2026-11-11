"""The Transform column through the Modbus interface: the base driver's DriverAgent applies it, the interface and the
proxy see raw register values only. Runs against the FakePPM; no proxy process or device."""
from types import SimpleNamespace
from unittest import mock

import pytest

from volttron.driver.base.config import DataSource, RemoteConfig
from volttron.driver.base.driver import DriverAgent
from volttron.driver.base.testing import FakePPM, serialized
from volttron.driver.interfaces.modbus.config import ModbusPointConfig
from volttron.driver.interfaces.modbus.modbus import Modbus

pytest.importorskip('icm.transforms')

DEVICE = 'campus/building/meter'


def T(name):
    return f'{DEVICE}/{name}'


def row(name, address, data_type='uint16', **extra):
    return ModbusPointConfig(volttron_point_name=name, address=address, data_type=data_type, **extra)


class FakeNode(SimpleNamespace):
    @property
    def data_source(self):
        return self.config.data_source


class FakeTree:
    def __init__(self):
        self.nodes = {}

    def add_points(self, device, configs):
        for config in configs:
            topic = '/'.join([device, config.volttron_point_name])
            self.nodes[topic] = FakeNode(identifier=topic, config=config, last_value=None, last_updated=None,
                                         is_point=True, meta_data={}, active=True)

    def get_node(self, topic):
        return self.nodes.get(topic)

    def device_points(self, device):
        return [n for t, n in self.nodes.items() if t.rsplit('/', 1)[0] == device]

    def is_active(self, topic):
        return True


@pytest.fixture
def ppm():
    Modbus.default_config = {}
    return FakePPM()


@pytest.fixture
def make_agent(ppm):
    """A DriverAgent around a real Modbus interface whose proxy manager is the FakePPM, with the given points."""
    def build(points, **remote):
        tree = FakeTree()
        tree.add_points(DEVICE, points)
        remote = {'driver_type': 'modbus', 'device_address': '10.0.0.4', **remote}
        with mock.patch('volttron.driver.base.proxy_interface.GeventProtocolProxyManager') as manager_class:
            manager_class.get_manager.return_value = ppm
            agent = DriverAgent(RemoteConfig(**remote), core=mock.Mock(), equipment_model=tree, scalability_test=None,
                                tz='UTC', unique_id='meter', vip=mock.Mock())
        agent.add_registers(points, DEVICE)                    # finalize_setup registers the remote with the fake proxy
        return agent, tree
    return build


def test_transform_column_is_the_base_configuration_field():
    cfg = ModbusPointConfig(**{'Volttron Point Name': 'V', 'Point Address': '1', 'Modbus Register': 'uint16',
                               'Transform': 'scale(0.1)'})
    assert cfg.transform == 'scale(0.1)'
    assert row('V', 1).transform == ''


def test_reads_decode_raw_then_scale(make_agent, ppm):
    agent, tree = make_agent([row('Volts', 1001, transform='scale(0.1)'), row('Plain', 1002)])
    assert agent.interface.point_map[T('Volts')].python_type is int                   # the register is still a uint16
    assert tree.nodes[T('Volts')].meta_data['type'] == 'float'                        # the published type follows scale
    ppm.queue(serialized({'1001': 2405, '1002': 7}))
    results, errors = agent.get_multiple_points([T('Volts'), T('Plain')])
    assert results == {T('Volts'): 240.5, T('Plain'): 7} and errors == {}


def test_writes_send_the_raw_register_value(make_agent, ppm):
    agent, tree = make_agent([row('Setpoint', 1010, writable=True, transform='transform(scale(0.1), add(-40))')])
    ppm.queue(serialized([{'address': 1010, 'count': 1}], [None]))
    assert agent.set_point(T('Setpoint'), 10.0) == 10.0
    assert ppm.payloads('WRITE_REGISTERS') == [{'register_map': 'holding', 'encode': True, 'write_mode': 'auto', 'queries': [[1010, None, 500]]}]


def test_modbus_tk_map_functions(make_agent, ppm):
    """The ION 6200 map's transforms: register-prefixed addresses, mod10k energy, scaled volts, a SunSpec factor."""
    holding = {'table': 'analog_output_holding_registers'}            # the map's own table spelling
    agent, tree = make_agent([row('kwh_del', 40138, 'uint32', transform='mod10k(True)', **holding),
                              row('vln_a', 40100, transform='scale(0.1)', **holding),
                              row('W', 40200, 'int16', transform='sunssf(W_SF)', **holding),
                              row('W_SF', 40201, 'int16', **holding)],
                             addressing='address')
    ppm.queue(serialized({'137': (5 << 16) | 7, '99': 2405, '199': 1234, '200': -1}))
    results, errors = agent.get_multiple_points([T('kwh_del'), T('vln_a'), T('W'), T('W_SF')])
    assert errors == {}
    assert results == {T('kwh_del'): 70005, T('vln_a'): 240.5, T('W'): 123.4, T('W_SF'): -1}
    assert agent.startup_read_topics == [T('W_SF')]


def test_served_values_are_seeded_raw(make_agent, ppm):
    """A served unit's registration carries the tree's last values inverted into register values."""
    tree = FakeTree()
    points = [row('Volts', 1001, writable=True, data_source='server', transform='scale(0.1)')]
    tree.add_points(DEVICE, points)
    tree.nodes[T('Volts')].last_value, tree.nodes[T('Volts')].last_updated = 240.5, object()
    with mock.patch('volttron.driver.base.proxy_interface.GeventProtocolProxyManager') as manager_class:
        manager_class.get_manager.return_value = ppm
        agent = DriverAgent(RemoteConfig(driver_type='modbus', driver_role='slave', bind_host='0.0.0.0', port=5020),
                            core=mock.Mock(), equipment_model=tree, scalability_test=None, tz='UTC', unique_id='served',
                            vip=mock.Mock())
    agent.add_registers(points, DEVICE)
    [registration] = ppm.payloads('REGISTER_REMOTE')
    assert registration['values'] == {T('Volts'): 2405}
