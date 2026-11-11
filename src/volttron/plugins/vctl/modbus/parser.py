"""``vctl modbus …``: Modbus driver tools that need no running platform. This module is a vctl plugin; importing it has
no side effects."""
from __future__ import annotations

import json
import sys

from pathlib import Path


def convert_ace(opts):
    from volttron.driver.interfaces.modbus.ace_conversion import convert_ace_device, write_conversion
    config = json.loads(Path(opts.config).read_text())
    conversion = convert_ace_device(config, opts.topic, opts.registry)
    written = write_conversion(conversion, Path(opts.out))
    for path in written:
        print(path)
    for note in conversion.notes:
        print(f'note: {note}', file=sys.stderr)
    return 0


def convert_ace_registry(opts):
    from volttron.driver.interfaces.modbus.ace_conversion import convert_ace_registry as convert
    conversion = convert(Path(opts.csv).read_text())
    text = conversion.files['registry.csv']
    if opts.out:
        Path(opts.out).write_text(text)
        print(opts.out)
    else:
        sys.stdout.write(text)
    for note in conversion.notes:
        print(f'note: {note}', file=sys.stderr)
    return 0


def build_modbus_commands(subparsers, add_parser):
    p = add_parser('convert-ace', help="Convert an ACE IoT modbus_enhanced device configuration (gateway, unit or legacy shape) "
                                       'to Modbus driver device configurations and registries.')
    p.add_argument('config', help='The ACE device configuration (JSON).')
    p.add_argument('topic', help='Device topic (devices/...); a gateway configuration puts one device per unit beneath it.')
    p.add_argument('-o', '--out', default='./converted', help='Directory for the .config and .csv files (default ./converted).')
    p.add_argument('--registry', help='config:// reference to use when the ACE configuration names none.')
    p.set_defaults(func=convert_ace)
    p = add_parser('convert-ace-registry', help="Rewrite an ACE registry CSV: named transforms become expressions, "
                                                'Mixed Endian becomes Byte Order.')
    p.add_argument('csv', help='The ACE registry CSV.')
    p.add_argument('-o', '--out', help='Output file (default: standard output).')
    p.set_defaults(func=convert_ace_registry)


try:
    from volttron.client.decorators import vctl_subparser
    from volttron.types.factories import ControlParser
except ImportError:                              # not a modular platform: nothing to register
    vctl_subparser = None

if vctl_subparser is not None:
    @vctl_subparser
    class ModbusVCtlParser(ControlParser):
        """``vctl modbus …``: Modbus driver tools."""

        class Meta:
            name = 'modbus'

        def configure(self, ctx):
            modbus = ctx.register_command('modbus', help='Modbus driver tools')
            subs = modbus.add_subparsers(title='subcommands', metavar='', dest='modbus_command', required=True)
            build_modbus_commands(subs, lambda name, **kw: ctx.register_subcommand(subs, name, **kw))
