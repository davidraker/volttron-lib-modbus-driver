"""Unit tests for volttron-lib-modbus-driver"""

from volttron.driver.interfaces.modbus.modbus import BaseInterface, Modbus


def test_driver():
    driver = Modbus()
    assert isinstance(driver, BaseInterface)
