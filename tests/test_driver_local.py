"""Platform-level test of the Modbus driver against a local modbus_tk server.

A real VOLTTRON platform (see the ``platform`` fixture) runs the Platform Driver, which polls a modbus_tk TCP server
started here through the Modbus Protocol Proxy. Points cover every struct data type in both byte orders, including the
legacy '<' little-endian forms, and are read and written through the Platform Driver's ``vdrv`` command-line tool.
"""
import csv
import json
import logging
import socket
import time

from random import randint
from struct import pack, unpack

import pytest

from . import helpers
from .client import Client, Field
from .conftest import PLATFORM_DRIVER
from .server import Server

logger = logging.getLogger(__name__)

DEVICE_TOPIC = 'devices/modbus'


def get_rand_ip_and_port():

    def is_port_open(ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        return result == 0

    def get_rand_port(ip=None, min_ip=5000, max_ip=6000):
        port = randint(min_ip, max_ip)
        if ip:
            while is_port_open(ip, port):
                port = randint(min_ip, max_ip)
        return port

    ip = "127.0.0.{}".format(randint(1, 254))
    port = get_rand_port(ip)
    return ip + ":{}".format(port)


IP, _port = get_rand_ip_and_port().split(":")
PORT = int(_port)

# Register values dictionary for testing set_point and get_point
REGISTERS_DICT = {
    "BigUShort": 2**16 - 1,
    "BigUInt": 2**32 - 1,
    "BigULong": 2**64 - 1,
    "BigShort": -(2**16) // 2,
    "BigInt": -(2**32) // 2,
    "BigFloat": -1234.0,
    "BigLong": -(2**64) // 2,
    "LittleUShort": 0,
    "LittleUInt": 0,
    "LittleULong": 0,
    "LittleShort": (2**16) // 2 - 1,
    "LittleInt": (2**32) // 2 - 1,
    "LittleFloat": 1.0,
    "LittleLong": (2**64) // 2 - 1
}

REGISTRY_CONFIG = [{"Volttron Point Name": "BigUShort", "Units": "PPM", "Modbus Register": ">H", "Writable": "TRUE",
                    "Point Address": "0"},
                   {"Volttron Point Name": "BigUInt", "Units": "PPM", "Modbus Register": ">I", "Writable": "TRUE",
                    "Point Address": "1"},
                   {"Volttron Point Name": "BigULong", "Units": "PPM", "Modbus Register": ">Q", "Writable": "TRUE",
                    "Point Address": "3"},
                   {"Volttron Point Name": "BigShort", "Units": "PPM", "Modbus Register": ">h", "Writable": "TRUE",
                    "Point Address": "7"},
                   {"Volttron Point Name": "BigInt", "Units": "PPM", "Modbus Register": ">i", "Writable": "TRUE",
                    "Point Address": "8"},
                   {"Volttron Point Name": "BigFloat", "Units": "PPM", "Modbus Register": ">f", "Writable": "TRUE",
                    "Point Address": "10"},
                   {"Volttron Point Name": "BigLong", "Units": "PPM", "Modbus Register": ">q", "Writable": "TRUE",
                    "Point Address": "12"},
                   {"Volttron Point Name": "LittleUShort", "Units": "PPM", "Modbus Register": "<H",
                    "Writable": "TRUE", "Point Address": "100"},
                   {"Volttron Point Name": "LittleUInt", "Units": "PPM", "Modbus Register": "<I",
                    "Writable": "TRUE", "Point Address": "101"},
                   {"Volttron Point Name": "LittleULong", "Units": "PPM", "Modbus Register": "<Q",
                    "Writable": "TRUE", "Point Address": "103"},
                   {"Volttron Point Name": "LittleShort", "Units": "PPM", "Modbus Register": "<h",
                    "Writable": "TRUE", "Point Address": "107"},
                   {"Volttron Point Name": "LittleInt", "Units": "PPM", "Modbus Register": "<i", "Writable": "TRUE",
                    "Point Address": "108"},
                   {"Volttron Point Name": "LittleFloat", "Units": "PPM", "Modbus Register": "<f",
                    "Writable": "TRUE", "Point Address": "110"},
                   {"Volttron Point Name": "LittleLong", "Units": "PPM", "Modbus Register": "<q",
                    "Writable": "TRUE", "Point Address": "112"}]

# Legacy form of the device configuration (driver_config, slave_id); the driver still accepts it.
DRIVER_CONFIG = {
    "driver_config": {
        "device_address": IP,
        "port": PORT,
        "slave_id": 1
    },
    "driver_type": "modbus",
    "registry_config": "config://modbus.csv",
    "interval": 120,
    "timezone": "UTC"
}


def topic(point_name: str) -> str:
    return f'{DEVICE_TOPIC}/{point_name}'


@pytest.fixture(scope="module")
def configured_driver(platform, tmp_path_factory):
    """Store the registry and device configuration and wait for the device to register with the proxy."""
    config_dir = tmp_path_factory.mktemp('config')
    registry = config_dir / 'modbus.csv'
    with open(registry, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(REGISTRY_CONFIG[0]))
        writer.writeheader()
        writer.writerows(REGISTRY_CONFIG)
    device = config_dir / 'modbus.config'
    device.write_text(json.dumps(DRIVER_CONFIG))
    platform.store_config(PLATFORM_DRIVER, 'modbus.csv', registry, csv=True)
    platform.store_config(PLATFORM_DRIVER, DEVICE_TOPIC, device)
    summary = platform.wait_for_log(r'Modbus .* holding table: 14 points, 0 pads, (\d+) request\(s\) per poll')
    logger.info(summary)
    return platform


class PPSPi32Client(Client):
    """
    Define some registers to PPSPi32Client
    """

    def __init__(self, *args, **kwargs):
        super(PPSPi32Client, self).__init__(*args, **kwargs)

    byte_order = helpers.BIG_ENDIAN
    addressing = helpers.ADDRESS_OFFSET

    BigUShort = Field("BigUShort", 0, helpers.USHORT, 'PPM', 2, helpers.no_op,
                      helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    BigUInt = Field("BigUInt", 1, helpers.UINT, 'PPM', 2, helpers.no_op,
                    helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    BigULong = Field("BigULong", 3, helpers.UINT64, 'PPM', 2, helpers.no_op,
                     helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    BigShort = Field("BigShort", 7, helpers.SHORT, 'PPM', 2, helpers.no_op,
                     helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    BigInt = Field("BigInt", 8, helpers.INT, 'PPM', 2, helpers.no_op, helpers.REGISTER_READ_WRITE,
                   helpers.OP_MODE_READ_WRITE)
    BigFloat = Field("BigFloat", 10, helpers.FLOAT, 'PPM', 2, helpers.no_op,
                     helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    BigLong = Field("BigLong", 12, helpers.INT64, 'PPM', 2, helpers.no_op,
                    helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    LittleUShort = Field("LittleUShort", 100, helpers.USHORT, 'PPM', 2, helpers.no_op,
                         helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    LittleUInt = Field("LittleUInt", 101, helpers.UINT, 'PPM', 2, helpers.no_op,
                       helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    LittleULong = Field("LittleULong", 103, helpers.UINT64, 'PPM', 2, helpers.no_op,
                        helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    LittleShort = Field("LittleShort", 107, helpers.SHORT, 'PPM', 2, helpers.no_op,
                        helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    LittleInt = Field("LittleInt", 108, helpers.INT, 'PPM', 2, helpers.no_op,
                      helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    LittleFloat = Field("LittleFloat", 110, helpers.FLOAT, 'PPM', 2, helpers.no_op,
                        helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)
    LittleLong = Field("LittleLong", 112, helpers.INT64, 'PPM', 2, helpers.no_op,
                       helpers.REGISTER_READ_WRITE, helpers.OP_MODE_READ_WRITE)


@pytest.fixture(scope="module")
def modbus_server():
    """One server for the module: test_default_values runs first and sees the zeros, test_set_point then writes."""
    modbus_server = Server(address=IP, port=PORT)
    modbus_server.define_slave(1, PPSPi32Client, unsigned=True)

    # Set values for registers from server as the default values
    modbus_server.set_values(1, PPSPi32Client().field_by_name("BigUShort"), 0)
    modbus_server.set_values(1, PPSPi32Client().field_by_name("BigUInt"), 0)
    modbus_server.set_values(1, PPSPi32Client().field_by_name("BigULong"), 0)
    modbus_server.set_values(1, PPSPi32Client().field_by_name("BigShort"), 0)
    modbus_server.set_values(1, PPSPi32Client().field_by_name("BigInt"), 0)
    modbus_server.set_values(1, PPSPi32Client().field_by_name("BigFloat"), 0)
    modbus_server.set_values(1, PPSPi32Client().field_by_name("BigLong"), 0)
    modbus_server.set_values(1,
                             PPSPi32Client().field_by_name("LittleUShort"),
                             unpack('<H', pack('>H', 0)))
    modbus_server.set_values(1,
                             PPSPi32Client().field_by_name("LittleUInt"),
                             unpack('<HH', pack('>I', 0)))
    modbus_server.set_values(1,
                             PPSPi32Client().field_by_name("LittleULong"),
                             unpack('<HHHH', pack('>Q', 0)))
    modbus_server.set_values(1,
                             PPSPi32Client().field_by_name("LittleShort"),
                             unpack('<H', pack('>h', 0)))
    modbus_server.set_values(1,
                             PPSPi32Client().field_by_name("LittleInt"),
                             unpack('<HH', pack('>i', 0)))
    modbus_server.set_values(1,
                             PPSPi32Client().field_by_name("LittleFloat"),
                             unpack('<HH', pack('>f', 0)))
    modbus_server.set_values(1,
                             PPSPi32Client().field_by_name("LittleLong"),
                             unpack('<HHHH', pack('>q', 0)))

    modbus_server.start()
    time.sleep(1)
    yield modbus_server
    modbus_server.stop()


def test_default_values(modbus_server, configured_driver):
    """
    By default server setting, all registers values are 0
    """
    default_values = configured_driver.get(DEVICE_TOPIC)
    assert set(default_values) == {topic(name) for name in REGISTERS_DICT}
    assert all(value == 0 for value in default_values.values()), default_values


def test_set_point(modbus_server, configured_driver):
    for key, value in REGISTERS_DICT.items():
        assert configured_driver.set_point(topic(key), value) == value
        assert configured_driver.get_point(topic(key)) == value

    all_values = configured_driver.get(DEVICE_TOPIC)
    assert all_values == {topic(name): value for name, value in REGISTERS_DICT.items()}
