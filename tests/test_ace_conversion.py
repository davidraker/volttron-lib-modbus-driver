"""Converting ACE IoT modbus_enhanced configurations and registries."""
import csv
import io
import json

from volttron.driver.interfaces.modbus.ace_conversion import (convert_ace_device, convert_ace_registry, convert_transform,
                                                              write_conversion)
from volttron.driver.interfaces.modbus.config import ModbusPointConfig, ModbusRemoteConfig

ACE_CSV = """Volttron Point Name,Point Address,Modbus Register,Units,Writable,Default Value,Transform,Notes,Mixed Endian,Byte Order,Word Order
voltage_l1,0,uint16,V,FALSE,,scale_0_1,Line 1,FALSE,,
power_total,12,int32,kW,FALSE,,W_to_kW,,FALSE,big,low
energy,20,float,kWh,TRUE,0,lambda x: x * 0.001,,TRUE,,
alarm_bit_3,50,uint16,,FALSE,,bit_3,,FALSE,,
status,40,uint16,,FALSE,,alarm_status,,FALSE,,
raw,60,float,,FALSE,,scale(0.001),,FALSE,little,
"""


def test_transform_names_become_expressions():
    notes = []
    assert convert_transform('scale_0_1', 'p', notes) == 'scale(0.1)'
    assert convert_transform('C_to_F', 'p', notes) == 'transform(scale(1.8), add(32))'
    assert convert_transform('error_to_none', 'p', notes).startswith('invalid(')
    assert convert_transform('bit_7', 'p', notes) == 'bit(7)' and convert_transform('mod10k(false)', 'p', notes) == 'mod10k(false)'
    assert convert_transform('lambda x: x * 2', 'p', notes) == '' and 'lambda' in notes[-1]
    assert convert_transform('combine_words', 'p', notes) == '' and 'derived point' in notes[-1]
    assert convert_transform('nosuch_thing', 'p', notes) == '' and 'unknown' in notes[-1]


def test_registry_conversion_rows_validate_as_modbus_points():
    conversion = convert_ace_registry(ACE_CSV)
    rows = list(csv.DictReader(io.StringIO(conversion.files['registry.csv'])))
    by_name = {r['Volttron Point Name']: r for r in rows}
    assert by_name['voltage_l1']['Transform'] == 'scale(0.1)'
    assert by_name['power_total'] == {**by_name['power_total'], 'Transform': 'scale(0.001)', 'Byte Order': 'big', 'Word Order': 'little'}
    assert by_name['energy']['Transform'] == '' and by_name['energy']['Byte Order'] == 'little' and by_name['energy']['Writable'] == 'TRUE'
    assert by_name['status']['Transform'].startswith('map(0') and by_name['raw']['Byte Order'] == 'little'
    assert any('Mixed Endian' in n for n in conversion.notes) and any('lambda' in n for n in conversion.notes)
    for row in rows:
        ModbusPointConfig(**row)                                        # every converted row is a valid point


def test_gateway_as_device_becomes_one_device_per_unit(tmp_path):
    config = {
        'driver_type': 'modbus_enhanced', 'interval': 10, 'timezone': 'UTC',
        'driver_config': {
            'gateway': {'connection_type': 'tcp', 'address': '192.168.1.100', 'port': 502, 'retry_attempts': 3, 'retry_backoff': 'exponential'},
            'units': [{'unit_id': 1, 'name': 'meter_1', 'registers': [{'name': 'kw', 'address': 12, 'type': 'float', 'units': 'kW', 'transform': 'W_to_kW'}]},
                      {'unit_id': 2, 'name': 'vfd', 'template': 'vfd_drive', 'register_offset': 100},
                      {'unit_id': '3', 'name': 'from_dict'}]},
        'registry_config': {'3': 'Volttron Point Name,Point Address,Modbus Register\nTemp,5,int16\n'}}
    conversion = convert_ace_device(config, 'devices/campus/b/gw1')
    files = conversion.files
    assert set(files) == {'devices__campus__b__gw1__meter_1.config', 'devices__campus__b__gw1__meter_1.csv',
                          'devices__campus__b__gw1__vfd.config', 'devices__campus__b__gw1__vfd.csv',
                          'devices__campus__b__gw1__from_dict.config', 'devices__campus__b__gw1__from_dict.csv'}
    meter = json.loads(files['devices__campus__b__gw1__meter_1.config'])
    assert meter['remote_config'] == {'driver_type': 'modbus', 'device_address': '192.168.1.100', 'unit_id': 1, 'port': 502, 'retries': 3}
    assert meter['interval'] == 10 and meter['registry_config'] == 'config://devices__campus__b__gw1__meter_1.csv'
    ModbusRemoteConfig(**meter['remote_config'])
    vfd_rows = list(csv.DictReader(io.StringIO(files['devices__campus__b__gw1__vfd.csv'])))
    assert vfd_rows[0]['Volttron Point Name'] == 'frequency_command' and vfd_rows[0]['Point Address'] == '100'
    assert vfd_rows[0]['Transform'] == 'scale(0.1)' and vfd_rows[0]['Writable'] == 'TRUE'
    assert list(csv.DictReader(io.StringIO(files['devices__campus__b__gw1__from_dict.csv'])))[0]['Volttron Point Name'] == 'Temp'
    assert any('retry_backoff' in n for n in conversion.notes) and any('one device per' in n for n in conversion.notes)
    written = write_conversion(conversion, tmp_path)
    assert (tmp_path / 'NOTES.txt').exists() and len(written) == 7


def test_unit_as_device_and_legacy_shapes():
    unit = convert_ace_device({'driver_type': 'modbus_enhanced', 'driver_config': {
        'gateway': {'connection_type': 'serial', 'address': '/dev/ttyUSB0', 'baudrate': 19200, 'parity': 'E'}, 'unit_id': 7},
        'registry_config': 'config://unit7.csv'}, 'devices/campus/b/u7')
    device = json.loads(unit.files['devices__campus__b__u7.config'])
    assert device['remote_config'] == {'driver_type': 'modbus', 'device_address': '/dev/ttyUSB0', 'unit_id': 7,
                                       'transport_protocol': 'serial', 'baudrate': 19200, 'parity': 'even'}
    assert device['registry_config'] == 'config://unit7.csv' and any('convert-ace-registry' in n for n in unit.notes)
    legacy = convert_ace_device({'driver_type': 'modbus_enhanced', 'driver_config': {'device_address': '10.0.0.4', 'port': 502, 'slave_id': 3},
                                 'registry_config': 'config://legacy.csv'}, 'devices/campus/b/legacy')
    assert json.loads(legacy.files['devices__campus__b__legacy.config'])['remote_config'] == {
        'driver_type': 'modbus', 'device_address': '10.0.0.4', 'unit_id': 3, 'port': 502}


def test_vctl_commands_build():
    import argparse
    from volttron.plugins.vctl.modbus.parser import build_modbus_commands
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers()
    build_modbus_commands(subs, subs.add_parser)
    opts = parser.parse_args(['convert-ace', 'x.json', 'devices/a/b', '-o', 'out'])
    assert opts.topic == 'devices/a/b' and opts.func.__name__ == 'convert_ace'
