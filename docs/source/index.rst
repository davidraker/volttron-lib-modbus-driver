.. _Modbus-Driver:

=============
Modbus Driver
=============

The VOLTTRON Modbus Driver interface allows the Platform Driver Agent to act as a client in communication with a
ModbusTCP server. First released in 1979 for use with PLCs, Modbus has become a common protocol for interacting
with remote devices. More information on the Modbus Protocol can be found `here <https://en.wikipedia.org/wiki/Modbus>`_

.. attention::

    VOLTTRON's modbus driver supports the ModbusTCP protocol only. For ModbusRTU support, see VOLTTRON's
    `Modbus-TK driver <Modbus-TK-Driver>`.


.. _Modbus-Config:

Modbus Device Configuration
===========================

The Modbus device configuration file follows the :ref:`device configuration file convention <Device-Configuration-File>`.
All devices using the Modbus interface should use "modbus" as the value of the ``driver_type`` key. Reference
:ref:`device configuration file convention <Device-Configuration-File>` for information on other standard device
configuration keys. Modbus specific configurations are contained in `driver_config`, a key-value dictionary used to
establish communication with a ModbusTCP server: The `driver_config` dictionary accepts three keys:

:device_address: IP Address of the device. (required)
:port: Port the device is listening on. (Defaults to 502 --- the standard Modbus port)
:slave_id: Slave ID of the device. (Defaults to 0.  Use 0 for no slave.)

A typical Modbus device configuration will have the form:

.. code-block:: json

    {
        "driver_config": {"device_address": "10.1.1.2",
                          "port": 502,
                          "slave_id": 5},
        "driver_type": "modbus",
        "registry_config":"config://registry_configs/hvac.csv",
        "interval": 60,
        "timezone": "UTC",
        "heart_beat_point": "heartbeat"
    }

This sample Modbus device configuration file can also be found in the volttron-lib-modbus-driver repository
`here <https://raw.githubusercontent.com/eclipse-volttron/volttron-lib-fake-driver/main/modbus_example.config>`_


.. _Modbus-Registry-Configuration:

Modbus Registry Configuration File
----------------------------------
The driver's registry configuration file specifies information related to each point on the device, in a CSV or JSON
file. More detailed information of driver registry files may be found :ref:`here <Registry-Configuration-File>`.
The driver’s registry configuration must contain the following items for each point:

:Volttron Point Name: The name by which the platform and agents running on the platform will refer to this point.
:Units: Used for meta data when creating point information on the historian.
:Modbus Register: A string representing how to interpret the binary format of the data register.
  The string takes two forms:

    + "BOOL" for coils and discrete inputs.
    + A format string for the Python struct module. See
      `the Python3 Struct docs <http://docs.python.org/3/library/struct.html>`_ for full documentation.  The
      supplied format string must only represent one value. See the documentation of your device to determine how to
      interpret the registers. Some Examples:

        * ">f" - A big endian 32-bit floating point number.
        * "<H" - A little endian 16-bit unsigned integer.
        * ">l" - A big endian 32-bit integer.

:Writable: Either `TRUE` or `FALSE`.  Determines if the point can be written to.
:Point Address: Modbus address of the point. Cannot include any offset value, it must be the exact value of the address.
:Mixed Endian: (Optional) Either `TRUE` or `FALSE`. If true, this will reverse the order of the Modbus registers that
 make up this point before parsing the value or writing it out to the device.  This setting has no effect on bit values.
:Default Value: The default value for the point.  When the point is reverted, it will change back to this value.
 If this value is missing it will revert to the last known value not set by an agent.

Any additional fields will be ignored.  It is common practice to include a `Point Name` or `Reference Point Name` to
include the device documentation's name for the point and `Notes` and `Unit Details` for additional information
about a point.

The following is an example of a Modbus registry configuration file (as CSV):

.. csv-table:: Catalyst 371
        :header: Reference Point Name,Volttron Point Name,Units,Units Details,Modbus Register,Writable,Point Address,Default Value,Notes

        CO2Sensor,ReturnAirCO2,PPM,0.00-2000.00,>f,FALSE,1001,,CO2 Reading 0.00-2000.0 ppm
        CO2Stpt,ReturnAirCO2Stpt,PPM,1000.00 (default),>f,TRUE,1011,1000,Setpoint to enable demand control ventilation
        Cool1Spd,CoolSupplyFanSpeed1,%,0.00 to 100.00 (75 default),>f,TRUE,1005,75,Fan speed on cool 1 call
        Cool2Spd,CoolSupplyFanSpeed2,%,0.00 to 100.00 (90 default),>f,TRUE,1007,90,Fan speed on Cool2 Call
        Damper,DamperSignal,%,0.00 - 100.00,>f,FALSE,1023,,Output to the economizer damper
        DaTemp,DischargeAirTemperature,F,(-)39.99 to 248.00,>f,FALSE,1009,,Discharge air reading
        ESMEconMin,ESMDamperMinPosition,%,0.00 to 100.00 (5 default),>f,TRUE,1013,5,Minimum damper position during the energy savings mode
        FanPower,SupplyFanPower, kW,0.00 to 100.00,>f,FALSE,1015,,Fan power from drive
        FanSpeed,SupplyFanSpeed,%,0.00 to 100.00,>f,FALSE,1003,,Fan speed from drive
        HeatCall1,HeatCall1,On / Off,on/off,BOOL,FALSE,1113,,Status indicator of heating stage 1 need
        HeartBeat,heartbeat,On / Off,on/off,BOOL,FALSE,1114,,Status indicator of heating stage 2 need

Another example registry file can also be found in the volttron-lib-modbus-driver repository
`here <https://raw.githubusercontent.com/eclipse-volttron/volttron-lib-fake-driver/main/modbus_example_registry.csv>`_.

