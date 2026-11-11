# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Installable Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2025 Battelle Memorial Institute
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# ===----------------------------------------------------------------------===
# }}}
"""Convert ACE IoT ``modbus_enhanced`` configurations to this driver's: one device configuration per unit, with the
registry each unit uses, and the Transform column rewritten from ACE's named transforms to expressions.

ACE's driver (``services/core/PlatformDriverAgent/platform_driver/interfaces/modbus_enhanced`` in the ACE-IoT-Solutions
fork of VOLTTRON) had three configuration shapes:

- *gateway as device*: ``driver_config.gateway`` plus ``driver_config.units``, one VOLTTRON device whose points were
  named ``<unit name>/<point>``; registries came from a dict keyed by unit id, from ``registers`` embedded in each unit,
  from a ``template`` in ``device_templates`` (or one of ACE's four built-in templates), or from one registry shared by
  every unit;
- *unit as device*: ``driver_config.gateway`` plus ``driver_config.unit_id``;
- *legacy*: ``device_address``, ``port``, ``slave_id`` or ``unit_id``, the shape of the Monolithic ``modbus`` driver.

This driver has one device per unit, sharing the gateway's connection in the proxy, so the first shape becomes several
configurations under the device topic (``<topic>/<unit name>``). Registries keep their columns; ``Transform`` cells are
rewritten (:data:`NAMED_TRANSFORMS`), ``Mixed Endian`` becomes ``Byte Order: little`` because ACE read it as byte order
where modbus_tk and this driver read word order, and anything that cannot be expressed is left blank with a note.
:func:`convert_ace_device` and :func:`convert_ace_registry` are pure; ``vctl modbus convert-ace`` writes their output.
"""
from __future__ import annotations

import copy
import csv
import io
import json
import re

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

#: ACE's named transforms as expressions of the icm.transforms library. ``None`` marks the ones with no equivalent.
NAMED_TRANSFORMS: dict[str, str | None] = {
    'scale_0_1': 'scale(0.1)', 'scale_0_01': 'scale(0.01)', 'scale_0_001': 'scale(0.001)', 'scale_0_0001': 'scale(0.0001)',
    'scale_10': 'scale(10)', 'scale_100': 'scale(100)', 'scale_1000': 'scale(1000)',
    'mA_to_A': 'scale(0.001)', 'A_to_mA': 'scale(1000)', 'W_to_kW': 'scale(0.001)', 'kW_to_W': 'scale(1000)',
    'W_to_MW': 'scale(0.000001)', 'MW_to_W': 'scale(1000000)', 'VAR_to_kVAR': 'scale(0.001)', 'kVAR_to_VAR': 'scale(1000)',
    'VA_to_kVA': 'scale(0.001)', 'kVA_to_VA': 'scale(1000)', 'Wh_to_kWh': 'scale(0.001)', 'kWh_to_Wh': 'scale(1000)',
    'Wh_to_MWh': 'scale(0.000001)', 'MWh_to_Wh': 'scale(1000000)',
    'C_to_F': 'transform(scale(1.8), add(32))', 'F_to_C': 'transform(add(-32), divide(1.8))',
    'C_to_K': 'add(273.15)', 'K_to_C': 'add(-273.15)',
    'ratio_to_percent': 'scale(100)', 'percent_to_ratio': 'scale(0.01)', 'pf_scale': 'divide(1000)',
    'percent_limit': 'clamp(0, 100)',
    'error_to_none': 'invalid(65535, 65534, 32768, -32768, -2147483648)', 'nan_to_none': 'finite()', 'inf_to_none': 'finite()',
    'bool_to_status': "map(0, 'OFF', 1, 'ON')", 'status_to_bool': 'bool()',
    'alarm_status': "map(0, 'Normal', 1, 'Warning', 2, 'Alarm', 3, 'Fault')",
    'binary_status': "transform(bit(0), select('Active', 'Inactive'))",
    **{f'bit_{i}': f'bit({i})' for i in range(16)},
    'combine_bytes': None, 'combine_words': None,
    'offset_1': 'add(1)', 'offset_minus_1': 'add(-1)', 'offset_10': 'add(10)', 'offset_minus_10': 'add(-10)',
    'offset_100': 'add(100)', 'offset_minus_100': 'add(-100)',
}
#: Notes on equivalents that are not exact.
TRANSFORM_NOTES = {
    'pf_scale': 'ACE returned None outside -1000..1000; divide(1000) has no such range check.',
    'bool_to_status': "ACE mapped any non-zero to 'ON'; map() names 0 and 1 only.",
    'status_to_bool': "ACE accepted 'ON', 'on', '1', 'true', 'True'; bool() accepts the usual spellings.",
    'alarm_status': "ACE returned 'Unknown' for other values; map() leaves them unchanged.",
}
#: ACE's built-in templates (config_template.py), for configurations that name them.
BUILTIN_TEMPLATES: dict[str, dict] = {
    'power_meter_basic': {'registers': [
        {'name': 'voltage_l1', 'address': 0, 'type': 'float', 'units': 'V'}, {'name': 'voltage_l2', 'address': 2, 'type': 'float', 'units': 'V'},
        {'name': 'voltage_l3', 'address': 4, 'type': 'float', 'units': 'V'}, {'name': 'current_l1', 'address': 6, 'type': 'float', 'units': 'A'},
        {'name': 'current_l2', 'address': 8, 'type': 'float', 'units': 'A'}, {'name': 'current_l3', 'address': 10, 'type': 'float', 'units': 'A'},
        {'name': 'power_total', 'address': 12, 'type': 'float', 'units': 'kW'}, {'name': 'energy_total', 'address': 14, 'type': 'float', 'units': 'kWh'},
        {'name': 'power_factor', 'address': 16, 'type': 'float', 'units': ''}, {'name': 'frequency', 'address': 18, 'type': 'float', 'units': 'Hz'}]},
    'temperature_sensor': {'registers': [
        {'name': 'temperature', 'address': 0, 'type': 'float', 'units': '°C'}, {'name': 'humidity', 'address': 2, 'type': 'float', 'units': '%'},
        {'name': 'setpoint', 'address': 4, 'type': 'float', 'units': '°C', 'writable': True},
        {'name': 'deadband', 'address': 6, 'type': 'float', 'units': '°C', 'writable': True}, {'name': 'status', 'address': 8, 'type': 'uint16'}]},
    'digital_io': {'registers': [{'name': f'input_{i}', 'address': i - 1, 'type': 'bit'} for i in range(1, 5)]
                   + [{'name': f'output_{i}', 'address': 9 + i, 'type': 'bit', 'writable': True} for i in range(1, 5)]},
    'vfd_drive': {'registers': [
        {'name': 'frequency_command', 'address': 0, 'type': 'uint16', 'units': 'Hz', 'writable': True, 'scale': 0.1},
        {'name': 'frequency_output', 'address': 1, 'type': 'uint16', 'units': 'Hz', 'scale': 0.1},
        {'name': 'current_output', 'address': 2, 'type': 'uint16', 'units': 'A', 'scale': 0.1},
        {'name': 'voltage_output', 'address': 3, 'type': 'uint16', 'units': 'V'}, {'name': 'motor_speed', 'address': 4, 'type': 'uint16', 'units': 'RPM'},
        {'name': 'torque', 'address': 5, 'type': 'int16', 'units': '%'}, {'name': 'status_word', 'address': 6, 'type': 'uint16'},
        {'name': 'control_word', 'address': 7, 'type': 'uint16', 'writable': True}, {'name': 'fault_code', 'address': 8, 'type': 'uint16'}]},
}
REGISTRY_COLUMNS = ['Volttron Point Name', 'Point Address', 'Modbus Register', 'Units', 'Writable', 'Default Value',
                    'Transform', 'Byte Order', 'Word Order', 'Notes']
_ACE_TYPES = {'bit': 'bool', 'float': 'float', 'int16': 'int16', 'uint16': 'uint16', 'int32': 'int32', 'uint32': 'uint32'}
_PARAMETRIC = re.compile(r'^\s*(\w+)\s*\((.*)\)\s*$')


@dataclass
class Conversion:
    """What a conversion produced: files to write (name -> text) and notes for the operator."""
    files: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def note(self, text: str):
        if text not in self.notes:
            self.notes.append(text)


# ---- registries ---------------------------------------------------------------------------------------------------------
def convert_transform(text: str, point: str, notes: list[str]) -> str:
    """ACE's Transform cell as an expression. Named transforms map through NAMED_TRANSFORMS, parameterised ones
    (``scale(0.001)``, ``mod10k(false)``, ``scale_reg(x)``) are already expressions, lambdas cannot be converted."""
    text = (text or '').strip()
    if not text:
        return ''
    if text.startswith('lambda'):
        notes.append(f'{point}: the lambda transform {text!r} cannot be converted; write it as an expression'
                     ' (scale, add, map, bit ...) and put it in the Transform column.')
        return ''
    if text in NAMED_TRANSFORMS:
        expression = NAMED_TRANSFORMS[text]
        if expression is None:
            notes.append(f'{point}: ACE transform {text!r} has no equivalent (it took two registers); use a derived point'
                         ' (Data Source static) over the two registers instead.')
            return ''
        if text in TRANSFORM_NOTES:
            notes.append(f'{point}: {text} -> {expression}. {TRANSFORM_NOTES[text]}')
        return expression
    if _PARAMETRIC.match(text):
        return text                              # modbus_tk forms pass through unchanged
    notes.append(f'{point}: unknown ACE transform {text!r}; left blank.')
    return ''


def convert_ace_registry_rows(rows: Iterable[dict], notes: list[str]) -> list[dict]:
    """ACE CSV rows (``Volttron Point Name``, ``Point Address``, ``Modbus Register`` or ``Type`` ...) as this driver's."""
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = (row.get('Volttron Point Name') or row.get('Point Name') or '').strip()
        if not name or name.startswith('#'):
            continue
        data_type = (row.get('Modbus Register') or row.get('Type') or 'uint16').strip()
        converted = {
            'Volttron Point Name': name,
            'Point Address': str(row.get('Point Address', row.get('Address', ''))).strip(),
            'Modbus Register': _ACE_TYPES.get(data_type.lower(), data_type),
            'Units': row.get('Units', ''),
            'Writable': 'TRUE' if str(row.get('Writable', '')).strip().lower() == 'true' else 'FALSE',
            'Default Value': row.get('Default Value', ''),
            'Transform': convert_transform(row.get('Transform', ''), name, notes),
            'Byte Order': '', 'Word Order': '',
            'Notes': row.get('Notes', row.get('Description', '')),
        }
        byte_order = str(row.get('Byte Order', '')).strip().lower()
        word_order = str(row.get('Word Order', '')).strip().lower()
        if byte_order:
            converted['Byte Order'] = 'little' if byte_order in ('little', '<', 'le') else 'big'
        elif str(row.get('Mixed Endian', '')).strip().lower() == 'true':
            converted['Byte Order'] = 'little'
            notes.append(f'{name}: ACE read Mixed Endian as little byte order, so it is written as Byte Order little.'
                         ' modbus_tk and this driver read Mixed Endian as word order; check the device.')
        if word_order:
            converted['Word Order'] = 'little' if word_order in ('little', '<', 'le', 'low') else 'big'
        out.append(converted)
    return out


def _json_register_to_row(register: dict) -> dict:
    """A register from an ACE JSON list (``name``, ``address``, ``type`` ...) as a CSV-style row."""
    if 'Point Address' in register or 'Volttron Point Name' in register:
        return dict(register)
    row = {'Volttron Point Name': register.get('name', ''), 'Point Address': register.get('address', ''),
           'Modbus Register': register.get('type', 'uint16'), 'Units': register.get('units', ''),
           'Writable': 'TRUE' if register.get('writable') else 'FALSE', 'Notes': register.get('description', ''),
           'Transform': register.get('transform', '') or register.get('transform_name', '')}
    if 'scale' in register and not row['Transform']:
        row['Transform'] = f"scale({register['scale']})"
    if register.get('byte_order'):
        row['Byte Order'] = register['byte_order']
    if register.get('word_order'):
        row['Word Order'] = register['word_order']
    if register.get('mixed_endian'):
        row['Mixed Endian'] = 'TRUE'
    return row


def rows_to_csv(rows: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=REGISTRY_COLUMNS, extrasaction='ignore', lineterminator='\n')
    writer.writeheader()
    for row in rows:
        writer.writerow({column: row.get(column, '') for column in REGISTRY_COLUMNS})
    return out.getvalue()


def convert_ace_registry(csv_text: str) -> Conversion:
    """An ACE registry CSV as this driver's registry CSV, with notes on what changed."""
    conversion = Conversion()
    rows = convert_ace_registry_rows(csv.DictReader(io.StringIO(csv_text)), conversion.notes)
    conversion.files['registry.csv'] = rows_to_csv(rows)
    return conversion


# ---- device configurations ---------------------------------------------------------------------------------------------
def _remote_config(gateway: dict, unit_id: int, notes: list[str]) -> dict:
    """This driver's remote_config for an ACE gateway block and a unit id."""
    transport = str(gateway.get('connection_type', 'tcp')).lower()
    remote = {'driver_type': 'modbus', 'device_address': gateway.get('address') or gateway.get('device_address'),
              'unit_id': int(unit_id)}
    if transport == 'serial':
        remote['transport_protocol'] = 'serial'
        for key in ('baudrate', 'bytesize', 'stopbits'):
            if key in gateway:
                remote[key] = gateway[key]
        if 'parity' in gateway:
            remote['parity'] = {'n': 'none', 'e': 'even', 'o': 'odd', 'm': 'mark', 's': 'space'}.get(str(gateway['parity']).lower()[:1], gateway['parity'])
    else:
        remote['port'] = int(gateway.get('port', 502))
    if 'timeout' in gateway:
        remote['timeout'] = gateway['timeout']
    if 'retry_attempts' in gateway:
        remote['retries'] = int(gateway['retry_attempts'])
    if 'retry_backoff' in gateway:
        notes.append('retry_backoff is not used: pymodbus spaces reconnects with its own exponential backoff.')
    return remote


def _unit_registers(unit: dict, registry_config: Any, templates: dict, notes: list[str]) -> list[dict]:
    """The CSV-style rows of one unit, from whichever source ACE allowed."""
    unit_id = str(unit.get('unit_id', unit.get('slave_id', '')))
    if isinstance(registry_config, dict) and unit_id in registry_config:
        source = registry_config[unit_id]
        if isinstance(source, str):
            if source.startswith('config://'):
                notes.append(f"unit {unit_id}: its registry is the configuration store entry {source[len('config://'):]!r};"
                             ' convert that CSV with convert-ace-registry and reference it from the device configuration.')
                return []
            return list(csv.DictReader(io.StringIO(source)))
        return [_json_register_to_row(r) for r in source if isinstance(r, dict)]
    if unit.get('registers'):
        return [_json_register_to_row(r) for r in unit['registers'] if isinstance(r, dict)]
    template_name = unit.get('template')
    if template_name:
        template = templates.get(template_name) or BUILTIN_TEMPLATES.get(template_name)
        if template is None:
            notes.append(f'unit {unit_id}: template {template_name!r} is not in device_templates or ACE\'s built-ins; no registry written.')
            return []
        registers = copy.deepcopy(template.get('registers', []))
        offset = int(unit.get('register_offset', 0) or 0)
        prefix = unit.get('name_prefix', '')
        named = template.get('transforms', {})
        for register in registers:
            register['address'] = int(register.get('address', 0)) + offset
            if prefix:
                register['name'] = f"{prefix}_{register['name']}"
            if 'transform_name' in register and register['transform_name'] in named:
                register['transform'] = named[register['transform_name']]
        return [_json_register_to_row(r) for r in registers]
    if isinstance(registry_config, list):
        return [_json_register_to_row(r) for r in registry_config if isinstance(r, dict)]
    if isinstance(registry_config, str) and registry_config.startswith('config://'):
        notes.append(f"unit {unit_id}: shares the registry {registry_config[len('config://'):]!r} from the configuration"
                     ' store; convert it with convert-ace-registry and reference it from each device configuration.')
        return []
    notes.append(f'unit {unit_id}: no registers found.')
    return []


def _device_file_name(topic: str) -> str:
    return topic.replace('/', '__') + '.config'


def convert_ace_device(config: dict, topic: str, registry_name: str | None = None) -> Conversion:
    """An ACE device configuration (any of its three shapes) as this driver's: ``files`` holds one ``.config`` per
    device (JSON) and the registry CSVs they reference; ``topic`` is the device's topic (``devices/...``), under which
    the units of a gateway-as-device configuration are placed by name."""
    conversion = Conversion()
    notes = conversion.notes
    driver_config = config.get('remote_config') or config.get('driver_config') or {}
    common = {k: v for k, v in config.items()
              if k not in ('driver_config', 'remote_config', 'driver_type', 'registry_config', 'device_templates')}
    registry_config = config.get('registry_config')
    templates = {**config.get('device_templates', {}), **driver_config.get('device_templates', {})}

    def write_device(device_topic: str, remote: dict, rows: list[dict] | None, registry_ref: str | None):
        device = {**common, 'driver_type': 'modbus', 'remote_config': remote}
        if rows is not None:
            csv_name = device_topic.replace('/', '__') + '.csv'
            converted = convert_ace_registry_rows(rows, notes)
            conversion.files[csv_name] = rows_to_csv(converted)
            device['registry_config'] = f'config://{csv_name}'
        elif registry_ref:
            device['registry_config'] = registry_ref
        conversion.files[_device_file_name(device_topic)] = json.dumps(device, indent=4) + '\n'

    if 'gateway' in driver_config and ('units' in driver_config or 'slaves' in driver_config):
        gateway = driver_config['gateway']
        for unit in driver_config.get('units') or driver_config.get('slaves') or []:
            unit_id = unit.get('unit_id', unit.get('slave_id'))
            if unit_id is None:
                notes.append(f'a unit without unit_id was skipped: {unit!r}')
                continue
            name = str(unit.get('name') or f'unit_{unit_id}')
            rows = _unit_registers(unit, registry_config, templates, notes)
            write_device(f'{topic}/{name}', _remote_config(gateway, int(unit_id), notes), rows or None, None)
        notes.append('ACE published these points as <unit name>/<point> under one device; they are now one device per'
                     ' unit beneath the gateway topic, sharing the gateway connection in the proxy.')
    elif 'gateway' in driver_config:
        gateway = driver_config['gateway']
        unit_id = driver_config.get('unit_id', driver_config.get('slave_id', 1))
        rows = (list(csv.DictReader(io.StringIO(registry_config))) if isinstance(registry_config, str) and '\n' in registry_config
                else [_json_register_to_row(r) for r in registry_config] if isinstance(registry_config, list) else None)
        ref = registry_config if isinstance(registry_config, str) and registry_config.startswith('config://') else registry_name
        write_device(topic, _remote_config(gateway, int(unit_id), notes), rows, ref)
        if ref and ref.startswith('config://'):
            notes.append(f"the registry {ref[len('config://'):]!r} stays in the configuration store; convert it with convert-ace-registry.")
    else:
        remote = {'driver_type': 'modbus', 'device_address': driver_config.get('device_address') or driver_config.get('ip_address'),
                  'unit_id': int(driver_config.get('slave_id', driver_config.get('unit_id', 1)))}
        if 'port' in driver_config:
            remote['port'] = int(driver_config['port'])
        else:
            remote['transport_protocol'] = 'serial'
            if 'baudrate' in driver_config:
                remote['baudrate'] = driver_config['baudrate']
        rows = ([_json_register_to_row(r) for r in registry_config] if isinstance(registry_config, list) else None)
        ref = registry_config if isinstance(registry_config, str) else registry_name
        write_device(topic, remote, rows, ref)
        if ref and str(ref).startswith('config://'):
            notes.append(f"the registry {str(ref)[len('config://'):]!r} stays in the configuration store; convert it with"
                         ' convert-ace-registry if its Transform column uses ACE names.')
    return conversion


def write_conversion(conversion: Conversion, out_dir: Path) -> list[Path]:
    """Write the conversion's files under out_dir (and NOTES.txt when there are notes); the paths written."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in conversion.files.items():
        path = out_dir / name
        path.write_text(text)
        written.append(path)
    if conversion.notes:
        path = out_dir / 'NOTES.txt'
        path.write_text('\n'.join(conversion.notes) + '\n')
        written.append(path)
    return written
