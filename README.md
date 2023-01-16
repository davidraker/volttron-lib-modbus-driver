# volttron-lib-modbus-driver

![Passing?](https://github.com/VOLTTRON/volttron-lib-modbus-driver/actions/workflows/run-tests.yml/badge.svg)
[![pypi version](https://img.shields.io/pypi/v/volttron-lib-modbus-driver.svg)](https://pypi.org/project/volttron-lib-modbus-driver/)

VOLTTRON’s modbus driver supports the Modbus over TCP/IP protocol only.

# Prerequisites

* Python 3.8

# Installation

1. Create and activate a virtual environment.

    ```shell
    python -m venv env
    source env/bin/activate
    ```

1. Install volttron and start the platform.

    ```shell
    pip install volttron

    # Start platform with output going to volttron.log
    volttron -vv -l volttron.log &
    ```

1. Install the volttron platform driver:

    ```shell
    vctl install volttron-platform-driver --vip-identity platform.driver --start
    ```

1. Install the volttron-lib-modbus-driver library.

    ```shell
    pip install volttron-lib-modbus-driver
    ```

1. Install the driver onto the Platform Driver.

    Installing a driver in the Platform Driver Agent requires adding copies of the device configuration and registry configuration files to the Platform Driver’s configuration store.

    Create a config directory and navigate to it:

    ```shell
    mkdir config
    cd config
    ```

    Navigate to the config directory and create a driver configuration file called `modbus.config`. There are three arguments for the driver_config section of the device configuration file:

    * device_address:  IP Address of the device.

    * port: Port the device is listening on. Defaults to 502 which is the standard port for Modbus devices.

    * slave_id:  Slave ID of the device. Defaults to 0. Use 0 for no slave.

    This repo provides an example configuration in the file "modbus_example.config".

    Here is an example device configuration file:

    ```json
    {
        "driver_config": {"device_address": "10.0.0.4"},
        "driver_type": "modbus",
        "registry_config":"config://catalyst371.csv",
        "interval": 120,
        "timezone": "UTC",
        "campus": "campus",
        "building": "building",
        "unit": "modbus1",
        "heart_beat_point": "ESMMode"
    }
    ```

    Create another file called `mobus.csv`. This CSV file will be your modbus registry configuration file. Each row configures a point on the device.

    The following columns are required for each row:

    * Volttron Point Name - The name by which the platform and agents running on the platform will refer to this point. For instance, if the Volttron Point Name is HeatCall1 (and using the example device configuration above) then an agent would use pnnl/isb2/hvac1/HeatCall1 to refer to the point when using the RPC interface of the actuator agent.

    * Units - Used for meta data when creating point information on the historian.

    * Modbus Register - A string representing how to interpret the data register and how to read it from the device. The string takes two forms:

        * “BOOL” for coils and discrete inputs.

        * A format string for the Python struct module. See the Python3 Struct docs for full documentation. The supplied format string must only represent one value. See the documentation of your device to determine how to interpret the registers. Some Examples:

        * “>f” - A big endian 32-bit floating point number.

        * “<H” - A little endian 16-bit unsigned integer.

        * “>l” - A big endian 32-bit integer.

    * Writable - Either TRUE or FALSE. Determines if the point can be written to. Only points labeled TRUE can be written to through the ActuatorAgent.

    * Point Address - Modbus address of the point. Cannot include any offset value, it must be the exact value of the address.

    * Mixed Endian - (Optional) Either TRUE or FALSE. For mixed endian values. This will reverse the order of the Modbus registers that make up this point before parsing the value or writing it out to the device. Has no effect on bit values.

    The following column is optional:

    * Default Value - The default value for the point. When the point is reverted by an agent it will change back to this value. If this value is missing it will revert to the last known value not set by an agent.

    Any additional columns will be ignored. It is common practice to include a Point Name or Reference Point Name to include the device documentation’s name for the point and Notes and Unit Details for additional information about a point.

    The following is an example of a Modbus registry configuration file:

    ```csv
    Reference Point Name,Volttron Point Name,Units,Units Details,Modbus Register,Writable,Point Address,Default Value,Notes
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
    ```

    Add modbus.csv and modbus.config to the configuration store:

    ```
    vctl config store platform.driver devices/campus/building/modbus modbus.config
    vctl config store platform.driver modbus.csv modbus.csv --csv
    ```

1. Observe Data

    To see data being published to the bus, install a [Listener Agent](https://pypi.org/project/volttron-listener/):

    ```
    vctl install volttron-listener --start
    ```

    Once installed, you should see the data being published by viewing the Volttron logs file that was created in step 2.
    To watch the logs, open a separate terminal and run the following command:

    ```
    tail -f <path to folder containing volttron.log>/volttron.log
    ```

# Development

Please see the following for contributing guidelines [contributing](https://github.com/eclipse-volttron/volttron-core/blob/develop/CONTRIBUTING.md).

Please see the following helpful guide about [developing modular VOLTTRON agents](https://github.com/eclipse-volttron/volttron-core/blob/develop/DEVELOPING_ON_MODULAR.md)


# Disclaimer Notice

This material was prepared as an account of work sponsored by an agency of the
United States Government.  Neither the United States Government nor the United
States Department of Energy, nor Battelle, nor any of their employees, nor any
jurisdiction or organization that has cooperated in the development of these
materials, makes any warranty, express or implied, or assumes any legal
liability or responsibility for the accuracy, completeness, or usefulness or any
information, apparatus, product, software, or process disclosed, or represents
that its use would not infringe privately owned rights.

Reference herein to any specific commercial product, process, or service by
trade name, trademark, manufacturer, or otherwise does not necessarily
constitute or imply its endorsement, recommendation, or favoring by the United
States Government or any agency thereof, or Battelle Memorial Institute. The
views and opinions of authors expressed herein do not necessarily state or
reflect those of the United States Government or any agency thereof.
