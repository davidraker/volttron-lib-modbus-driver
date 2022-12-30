import os

import gevent
import pytest
from volttron.client.known_identities import CONFIGURATION_STORE, PLATFORM_DRIVER
from volttron.utils import jsonapi
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
    point_name = "SupplyTemp"
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

    config = {
        "driver_scrape_interval": 0.05,
        "publish_breadth_first_all": "false",
        "publish_depth_first": "false",
        "publish_breadth_first": "false"
    }
    puid = vi.install_agent(agent_dir="volttron-platform-driver",
                            config_file=config,
                            start=False,
                            vip_identity=PLATFORM_DRIVER)
    assert puid is not None
    gevent.sleep(1)
    assert vi.start_agent(puid)
    assert vi.is_agent_running(puid)

    # create the publish agent
    publish_agent = volttron_instance.build_agent()
    assert publish_agent.core.identity
    gevent.sleep(1)

    capabilities = {"edit_config_store": {"identity": PLATFORM_DRIVER}}
    volttron_instance.add_capabilities(publish_agent.core.publickey, capabilities)

    # Add Modbus Driver to Platform Driver
    registry_config_string = """Volttron Point Name,Units,Writable,Point Address,Notes,Modbus Register,Multiplier
    SupplyTemp,degC,FALSE,0,,>H,100
    Demand,%,FALSE,26,,>H,1
    SecondStageCoolingDemandSetPoint,None,TRUE,14,,>H,1"""

    publish_agent.vip.rpc.call(CONFIGURATION_STORE,
                               "manage_store",
                               PLATFORM_DRIVER,
                               "modbus.csv",
                               registry_config_string,
                               config_type="csv")
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
                               jsonapi.dumps(driver_config),
                               config_type='json')

    gevent.sleep(120)

    yield publish_agent

    volttron_instance.stop_agent(puid)
    publish_agent.core.stop()