"""Legacy-compatibility and device-level features of the Modbus interface: Bit points, the exception-status table,
device identification, serial inference, Byte Order, legacy keys, duplicate addresses and the health hook."""
import logging

from unittest import mock

import pytest

from volttron.driver.base.config import RemoteConfig
from volttron.driver.interfaces.modbus.config import ByteOrder, ModbusPointConfig, ModbusRemoteConfig, Table, TransportProtocol
from volttron.driver.interfaces.modbus.modbus import Modbus

from tests.conftest import TOPIC, point, serialized


class TestBitPoints:
    def test_bit_rows_share_one_register_declaration(self, make_interface, ppm):
        iface = make_interface([point('Status', 1010, 'uint16'), point('Fault', 1010, 'uint16', bit=3),
                                point('Run', 1010, 'uint16', bit=0, writable=True)])
        fault, run = iface.point_map[TOPIC('Fault')], iface.point_map[TOPIC('Run')]
        assert fault.python_type is bool and fault.bit == 3 and fault.table is Table.input and run.table is Table.holding
        tables = iface.registration_payload()['tables']
        assert [f['address'] for f in tables['input']] == [1010] and [f['address'] for f in tables['holding']] == [1010]

    def test_bit_row_without_a_type_is_a_uint16(self):
        cfg = ModbusPointConfig(**{'Volttron Point Name': 'Fault', 'Point Address': '1010', 'Bit': '3'})
        assert cfg.data_type == 'uint16' and cfg.bit == 3

    def test_conflicting_declarations_of_one_register_are_an_error(self, make_interface):
        iface = make_interface([point('Status', 1010, 'uint16'), point('Energy', 1010, 'uint32')])
        with pytest.raises(ValueError, match='declare the same input register 1010 differently'):
            iface.registration_payload()

    def test_bits_are_read_from_the_shared_word(self, make_interface, ppm):
        iface = make_interface([point('Status', 1010, 'uint16'), point('Fault', 1010, 'uint16', bit=3),
                                point('Alarm', 1010, 'uint16', bit=0)])
        iface.proxy_peer = ppm.peer
        ppm.queue(serialized({'1010': 0b1001}))
        results, errors = iface.get_multiple_points([TOPIC('Status'), TOPIC('Fault'), TOPIC('Alarm')])
        assert results == {TOPIC('Status'): 9, TOPIC('Fault'): True, TOPIC('Alarm'): True} and errors == {}
        assert 'queries' not in ppm.payloads()[0]                      # the whole table: one request for all three

    def test_bit_writes_carry_the_bit_index(self, make_interface, ppm):
        iface = make_interface([point('Run', 1010, 'uint16', bit=0, writable=True)])
        iface.proxy_peer = ppm.peer
        ppm.queue(serialized([{'address': 1010, 'count': 1, 'bit': 0}], [None]))
        assert iface.set_point(TOPIC('Run'), 'true') is True
        assert ppm.payloads('WRITE_REGISTERS')[0]['queries'] == [[1010, None, True, 0]]

    @pytest.mark.parametrize('kwargs, message', [
        ({'data_type': 'bool', 'bit': 1}, 'holding or input register'),      # bool lands in a bit table
        ({'data_type': 'uint32', 'bit': 1}, 'one 16-bit register'),
        ({'data_type': 'uint16', 'bit': 1, 'table': 'holding', 'data_source': 'server'}, 'served unit'),
    ])
    def test_bit_validation(self, make_interface, kwargs, message):
        iface = make_interface([])
        with pytest.raises(ValueError, match=message):
            iface.create_register(ModbusPointConfig(volttron_point_name='p', address=5, **kwargs))


class TestExceptionStatus:
    def test_table_point_reads_the_status_byte(self, make_interface, ppm):
        iface = make_interface([point('Exc', 0, 'uint16', table='exception_status'), point('Mode', 1010, 'uint16', writable=True)])
        iface.proxy_peer = ppm.peer
        assert 'exception_status' not in iface.registration_payload()['tables']
        ppm.queue(serialized([[5]], [None]), serialized({'1010': 3}))
        results, errors = iface.get_multiple_points([TOPIC('Exc'), TOPIC('Mode')])
        assert results == {TOPIC('Exc'): 5, TOPIC('Mode'): 3} and errors == {}
        assert ppm.payloads()[0] == {'register_map': 'exception_status', 'queries': [[0, 1]]}
        with pytest.raises(ValueError, match='read-only'):
            iface.create_register(point('W', 0, 'uint16', table='exception_status', writable=True))


class TestDeviceLevelCalls:
    def test_device_identification_at_registration(self, ppm):
        from volttron.driver.base.testing import build_interface
        ppm.queue(serialized({}), serialized({'objects': {'VendorName': 'ACME', 'ProductCode': 'X-1'}}),
                  serialized({'objects': {'ModelName': 'M-9'}}))
        iface = build_interface(Modbus, {'driver_type': 'modbus', 'device_address': '10.0.0.4', 'device_identification': True},
                                driver_agent=mock.Mock(equipment_model=None), ppm=ppm)
        iface.finalize_setup(initial_setup=True)
        assert [p.get('read_code') for p in ppm.payloads('READ_DEVICE_INFORMATION')] == [1, 2]
        assert iface.device_identification == {'VendorName': 'ACME', 'ProductCode': 'X-1', 'ModelName': 'M-9'}

    def test_callables_are_declared_and_keyed_by_device(self, interface, ppm):
        assert {'read_device_information', 'read_exception_status', 'modbus_diagnostics', 'file_record', 'modbus_status'} <= Modbus.interface_callable_methods
        ppm.queue(serialized({'status': 5, 'bits': [True, False, True, False, False, False, False, False]}))
        results, errors = interface.read_exception_status([TOPIC('Mode')])
        assert results == {'campus/building/rtu': {'status': 5, 'bits': [True, False, True, False, False, False, False, False]}} and errors == {}
        ppm.queue(serialized({'function': 'query_data', 'message': ['hi']}))
        results, _ = interface.modbus_diagnostics([TOPIC('Mode')], 'query_data', msg='hi')
        assert results['campus/building/rtu']['message'] == ['hi']
        assert ppm.payloads('DIAGNOSTICS') == [{'function': 'query_data', 'arguments': {'msg': 'hi'}}]
        ppm.queue(serialized({}, {'file_record': 'nope'}))
        results, errors = interface.file_record([TOPIC('Mode')], 'read', [{'file_number': 1, 'record_number': 0, 'record_length': 2}])
        assert results == {} and errors == {'campus/building/rtu': 'nope'}

    def test_health_merges_the_proxy_status(self, interface, ppm):
        ppm.queue(serialized({'connected': True, 'connection': {'reconnects': 2}, 'units': {'1': {'requests': 9}},
                              'refused_single_writes': ['1:holding'], 'refused_multiple_writes': [], 'refused_mask_writes': []}))
        health = interface.health()
        assert health['protocol'] == 'modbus' and health['connected'] is True and health['unit'] == {'requests': 9}
        assert health['refused_single_writes'] == ['1:holding'] and health['connection']['reconnects'] == 2
        interface.proxy_peer = None
        assert interface.health()['proxy'] == 'not connected'


class TestLegacyDeviceConfiguration:
    @pytest.mark.parametrize('address, extra, transport', [
        ('/dev/ttyUSB0', {}, TransportProtocol.serial), ('COM3', {}, TransportProtocol.serial),
        ('10.0.0.4', {'port': 0}, TransportProtocol.serial), ('10.0.0.4', {}, TransportProtocol.tcp),
        ('/dev/ttyUSB0', {'transport_protocol': 'tcp'}, TransportProtocol.tcp),          # explicit wins
    ])
    def test_serial_is_inferred_from_the_address_or_port_zero(self, address, extra, transport):
        cfg = ModbusRemoteConfig(driver_type='modbus', device_address=address, **extra)
        assert cfg.transport_protocol is transport

    def test_legacy_keys_are_mapped_or_explained(self, caplog):
        with caplog.at_level(logging.INFO):
            cfg = ModbusRemoteConfig(driver_type='modbus', ip_address='10.0.0.9', retry_attempts=5, xonxoff=0, name='m',
                                     retry_backoff='exponential', bogus=1)
        assert cfg.device_address == '10.0.0.9' and cfg.retries == 5
        assert 'xonxoff' in caplog.text and 'retry_backoff' in caplog.text and 'retry_attempts is read as retries' in caplog.text
        assert cfg.unknown_keys() == ['bogus']

    def test_unknown_keys_are_warned_about_at_setup(self, make_interface, caplog):
        with caplog.at_level(logging.WARNING):
            make_interface([], bogus=1, another='x')
        assert 'configuration keys not used by the Modbus driver: another, bogus' in caplog.text

    def test_byte_order_column_and_device_default(self, make_interface):
        iface = make_interface([point('A', 1, 'uint16'), point('B', 2, 'uint16', byte_order='little'),
                                point('C', 3, '>f', **{'Byte Order': '<'})], byte_order='big')
        assert not iface.point_map[TOPIC('A')].spec.byte_swap and iface.point_map[TOPIC('B')].spec.byte_swap
        assert iface.point_map[TOPIC('C')].spec.byte_swap
        iface = make_interface([point('A', 1, 'uint16')], byte_order='little')
        assert iface.point_map[TOPIC('A')].spec.byte_swap and iface.config.byte_order is ByteOrder.little

    def test_bool_and_array_spellings(self, make_interface):
        iface = make_interface([point('Flag', 1, 'bool', table='holding'), point('Arr', 2, 'array(int16, 4)'), point('Bits', 6, 'bits', table='holding')])
        flag, arr, bits = (iface.point_map[TOPIC(n)] for n in ('Flag', 'Arr', 'Bits'))
        assert flag.spec.boolean and flag.python_type is bool and flag.spec_fields()['boolean'] is True
        assert arr.spec.count == 4 and not bits.spec.boolean


class TestDuplicateAddresses:
    def rows(self, **second):
        base = {'Volttron Point Name': 'Volts AB', 'Point Address': '999', 'Modbus Register': 'float', 'Table': 'holding'}
        dup = {'Volttron Point Name': 'Volts AB Copy', 'Point Address': '999', 'Modbus Register': 'float', 'Table': 'holding', **second}
        return [base, dup, {'Volttron Point Name': 'Amps', 'Point Address': '1001', 'Modbus Register': 'float', 'Table': 'holding'}]

    def test_identical_duplicate_becomes_a_derived_point(self, make_interface, caplog):
        iface = make_interface([])
        with caplog.at_level(logging.WARNING):
            rows = iface.prepare_registry_config(self.rows())
        assert len(rows) == 3 and rows[1]['data_source'] == 'virtual' and rows[1]['transform'] == "value_of('Volts AB')"
        assert 'read as a derived point' in caplog.text

    def test_duplicate_with_its_own_transform_keeps_it_after_value_of(self, make_interface):
        iface = make_interface([])
        rows = iface.prepare_registry_config(self.rows(Transform='scale(0.001)'))
        assert rows[1]['transform'] == "transform(value_of('Volts AB'), scale(0.001))"
        rows = iface.prepare_registry_config(self.rows(Transform='transform(scale(0.1), add(1))'))
        assert rows[1]['transform'] == "transform(value_of('Volts AB'), scale(0.1), add(1))"

    def test_conflicting_duplicate_is_dropped(self, make_interface, caplog):
        iface = make_interface([])
        with caplog.at_level(logging.WARNING):
            rows = iface.prepare_registry_config(self.rows(**{'Modbus Register': 'uint32'}))
        assert [r['Volttron Point Name'] for r in rows] == ['Volts AB', 'Amps'] and 'dropping Volts AB Copy' in caplog.text

    def test_bit_rows_and_pads_are_not_duplicates(self, make_interface):
        iface = make_interface([])
        rows = iface.prepare_registry_config([
            {'Volttron Point Name': 'Status', 'Point Address': '10', 'Modbus Register': 'uint16'},
            {'Volttron Point Name': 'Fault', 'Point Address': '10', 'Bit': '3'},
            {'Volttron Point Name': 'gap', 'Point Address': '10', 'Modbus Register': 'pad', 'Table': 'input'}])
        assert len(rows) == 3 and all('transform' not in r for r in rows)
