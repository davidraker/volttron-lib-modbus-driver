import gevent
import json
import os
import pytest

from volttron.client.known_identities import CONFIGURATION_STORE, PLATFORM_DRIVER

from volttrontesting.platformwrapper import PlatformWrapper

MODBUS_TEST_IP = "MODBUS_TEST_IP"

# apply skipif to all tests
skip_msg = f"Env var {MODBUS_TEST_IP} not set. Please set the env var to the proper IP to run this integration test."
pytestmark = pytest.mark.skipif(os.environ.get(MODBUS_TEST_IP) is None, reason=skip_msg)


def test_get_point(publish_agent):
    registers = ["SupplyTemp", "Demand", "SecondStageCoolingDemandSetPoint"]
    for point_name in registers:
        point_val = publish_agent.vip.rpc.call(PLATFORM_DRIVER, "get_point", "modbus",
                                               point_name).get(timeout=10)
        print(f"Point: {point_name} has point value of {point_val}")
        assert isinstance(point_val, int)


def test_set_point(publish_agent):
    point_name = "SecondStageCoolingDemandSetPoint"
    point_val = 42
    publish_agent.vip.rpc.call(PLATFORM_DRIVER, "set_point", "modbus", point_name,
                               point_val).get(timeout=10)
    assert publish_agent.vip.rpc.call(PLATFORM_DRIVER, "get_point", "modbus",
                                      point_name).get(timeout=10) == point_val


@pytest.fixture(scope="module")
def publish_agent(volttron_instance: PlatformWrapper):
    assert volttron_instance.is_running()
    vi = volttron_instance
    assert vi is not None
    assert vi.is_running()

    # create the publish agent
    publish_agent = volttron_instance.build_agent()
    assert publish_agent.core.identity
    gevent.sleep(1)

    capabilities = {"edit_config_store": {"identity": PLATFORM_DRIVER}}
    volttron_instance.add_capabilities(publish_agent.core.publickey, capabilities)
    gevent.sleep(1)

    # Add Modbus Driver to Platform Driver
    registry_config = [
        {
            "Volttron Point Name": "SupplyTemp",
            "Units": "degC",
            "Writable": "FALSE",
            "Point Address": "0",
            "Notes": "",
            "Modbus Register": ">H",
            "Multiplier": "100"
        },
        {
            "Volttron Point Name": "Demand",
            "Units": "%",
            "Writable": "FALSE",
            "Point Address": "26",
            "Notes": "",
            "Modbus Register": ">H",
            "Multiplier": "1"
        },
        {
            "Volttron Point Name": "SecondStageCoolingDemandSetPoint",
            "Units": "None",
            "Writable": "TRUE",
            "Point Address": "14",
            "Notes": "",
            "Modbus Register": ">H",
            "Multiplier": "1"
        }
    ]
    publish_agent.vip.rpc.call(CONFIGURATION_STORE,
                               "manage_store",
                               PLATFORM_DRIVER,
                               "modbus.csv",
                               json.dumps(registry_config),
                               config_type="json").get(timeout=10)
    device_address = os.environ.get(MODBUS_TEST_IP)
    driver_config = {
        "driver_config": {
            "device_address": device_address,
            "port": 502,
            "slave_id": 8
        },
        "driver_type": "modbus",
        "registry_config": "config://modbus.csv",
        "interval": 5,
        "timezone": "US/Pacific",
        "campus": "PNNL",
        "building": "DEMO",
        "unit": "M2000"
    }
    publish_agent.vip.rpc.call(CONFIGURATION_STORE,
                               "manage_store",
                               PLATFORM_DRIVER,
                               "devices/modbus",
                               json.dumps(driver_config),
                               config_type='json').get(timeout=10)

    puid = vi.install_agent(agent_dir="volttron-platform-driver",
                            # config_file=config,
                            start=False,
                            vip_identity=PLATFORM_DRIVER)
    assert puid is not None
    gevent.sleep(1)
    assert vi.start_agent(puid)
    assert vi.is_agent_running(puid)

    yield publish_agent

    volttron_instance.stop_agent(puid)
    publish_agent.core.stop()
