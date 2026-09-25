"""Configuration models for the Modbus driver interface."""
from enum import Enum
from typing import Any

from pydantic import AliasChoices, Field, field_validator, model_validator

from volttron.driver.base.config import PointConfig, RemoteConfig


class Table(str, Enum):
    """The four Modbus data tables, named as the Modbus Protocol Proxy knows them."""
    coil = 'coil'
    discrete_input = 'discrete_input'
    holding = 'holding'
    input = 'input'

    @property
    def read_only(self) -> bool:
        return self in (Table.discrete_input, Table.input)

    @property
    def is_bits(self) -> bool:
        return self in (Table.coil, Table.discrete_input)


# Accepted spellings of table names, including those used by the modbus_tk driver.
TABLE_ALIASES: dict[str, Table] = {
    'coil': Table.coil, 'coils': Table.coil, 'discrete_output_coils': Table.coil, 'discrete_output': Table.coil,
    'discrete_input': Table.discrete_input, 'discrete_inputs': Table.discrete_input, 'contact': Table.discrete_input,
    'contacts': Table.discrete_input, 'discrete_input_contacts': Table.discrete_input,
    'holding': Table.holding, 'holding_register': Table.holding, 'holding_registers': Table.holding,
    'analog_output_holding_registers': Table.holding, 'analog_output': Table.holding,
    'input': Table.input, 'input_register': Table.input, 'input_registers': Table.input,
    'analog_input_registers': Table.input, 'analog_input': Table.input,
}

# First address of each table in "Modbus addressing" (e.g., 40001 is the first holding register).
TABLE_BASE_ADDRESS: dict[Table, int] = {Table.coil: 1, Table.discrete_input: 10001, Table.input: 30001,
                                        Table.holding: 40001}


class Addressing(str, Enum):
    """How addresses in the registry are expressed.

    offset: the zero-based protocol address (default; 'exact' is accepted as a synonym).
    offset_plus: one-based, as printed in many vendor manuals; 1 is subtracted.
    address: table-prefixed one-based (1, 10001, 30001, 40001 ranges); the table base is subtracted.
    """
    offset = 'offset'
    offset_plus = 'offset_plus'
    address = 'address'

    def resolve(self, address: int, table: Table) -> int:
        match self:
            case Addressing.offset:
                resolved = address
            case Addressing.offset_plus:
                resolved = address - 1
            case Addressing.address:
                resolved = address - TABLE_BASE_ADDRESS[table]
        if resolved < 0:
            raise ValueError(f"Address {address} is out of range for the {table.value} table with {self.value} addressing.")
        return resolved


class WordOrder(str, Enum):
    big = 'big'
    little = 'little'


class Parity(str, Enum):
    none = 'none'
    even = 'even'
    odd = 'odd'
    mark = 'mark'
    space = 'space'

    @property
    def pymodbus(self) -> str:
        return self.value[0].upper()


class StopBits(float, Enum):
    one = 1
    one_point_five = 1.5
    two = 2


class TransportProtocol(str, Enum):
    tcp = 'tcp'
    udp = 'udp'
    serial = 'serial'
    tls = 'tls'


def _lower_or_none(v):
    if v is None or (isinstance(v, str) and not v.strip()):
        return None
    return v.strip().lower() if isinstance(v, str) else v


_DATA_TYPE_KEYS = ('data_type', 'Data Type', 'data_format', 'Data Format', 'modbus_register', 'Modbus Register',
                   'type', 'Type')
_PAD_TYPE_NAMES = ('pad', 'padding', 'reserved', 'skip')


def is_pad_type(data_type: str) -> bool:
    return data_type.strip().lower().split('[')[0].strip() in _PAD_TYPE_NAMES


class ModbusPointConfig(PointConfig):
    address: int = Field(validation_alias=AliasChoices('address', 'point_address', 'Address', 'Point Address'))
    # Any spelling accepted by the proxy's parse_data_type: pymodbus names (UINT16), modbus_tk names (float,
    # string[8]), or struct formats (>f, 4H). A data_type of 'pad' marks registers to read but not publish.
    data_type: str = Field(validation_alias=AliasChoices('data_type', 'Data Type', 'data_format', 'Data Format',
                                                         'modbus_register', 'Modbus Register', 'type', 'Type'))
    # Number of registers (or coils); usually implied by data_type. Required for strings without a length.
    count: int | None = Field(default=None, validation_alias=AliasChoices('count', 'Count', 'length', 'Length'))
    # Defaults from data_type and writable when omitted: booleans go to coil/discrete_input, all else to
    # holding/input.
    table: Table | None = Field(default=None, validation_alias=AliasChoices('table', 'Table'))
    word_order: WordOrder | None = Field(default=None, validation_alias=AliasChoices('word_order', 'Word Order'))
    # Legacy spelling of word_order='little'.
    mixed_endian: bool = Field(default=False, validation_alias=AliasChoices('mixed_endian', 'Mixed Endian', 'mixed'))
    string_encoding: str = Field(default='utf-8', validation_alias=AliasChoices('string_encoding', 'String Encoding'))
    default_value: Any = Field(default=None, validation_alias=AliasChoices('default_value', 'Default Value'))
    description: str = Field(default='', validation_alias=AliasChoices('description', 'Description'))
    # Kept for modbus_tk registry compatibility; a synonym for reference_point_name.
    register_name: str = Field(default='', validation_alias=AliasChoices('register_name', 'Register Name'))
    # TODO: transform is not yet implemented; it should be handled by the base driver for all interfaces.
    transform: str = Field(default='', validation_alias=AliasChoices('transform', 'Transform'))

    @model_validator(mode='before')
    @classmethod
    def _pads_are_not_points(cls, data):
        """A pad row describes registers to read through, not a point.

        The platform builds its equipment tree from these configs before the interface sees them, so the row marks
        itself inactive and never-polled here. It is then never scheduled, published, or requested from the interface.
        """
        if isinstance(data, dict):
            data_type = next((data[k] for k in _DATA_TYPE_KEYS if k in data), None)
            if isinstance(data_type, str) and is_pad_type(data_type):
                overridden = ('active', 'data_source', 'Data Source', 'writable', 'Writable')
                data = {**{k: v for k, v in data.items() if k not in overridden},
                        'active': False, 'data_source': 'never', 'writable': False}
        return data

    @field_validator('table', mode='before')
    @classmethod
    def _normalize_table(cls, v):
        v = _lower_or_none(v)
        if v is None or isinstance(v, Table):
            return v
        try:
            return TABLE_ALIASES[v.replace(' ', '_').replace('-', '_')]
        except KeyError:
            raise ValueError(f"Unknown Modbus table {v!r}. Use one of: {', '.join(t.value for t in Table)}")

    @field_validator('word_order', mode='before')
    @classmethod
    def _normalize_word_order(cls, v):
        return _lower_or_none(v)

    @field_validator('count', mode='before')
    @classmethod
    def _empty_count(cls, v):
        return None if v == '' else v

    @property
    def is_pad(self) -> bool:
        return is_pad_type(self.data_type)


class ModbusRemoteConfig(RemoteConfig):
    transport_protocol: TransportProtocol = Field(default=TransportProtocol.tcp,
                                                  validation_alias=AliasChoices('transport_protocol', 'transport'))
    device_address: str
    # None resolves to 802 for TLS and 502 otherwise. Ignored for serial.
    port: int | None = None
    unit_id: int = Field(default=1, validation_alias=AliasChoices('unit_id', 'device_id', 'slave_id'))
    addressing: Addressing = Field(default=Addressing.offset)
    # Default word order for multi-register values; a point may override it.
    word_order: WordOrder = Field(default=WordOrder.big, validation_alias=AliasChoices('word_order', 'endian'))
    # Largest run of unconfigured registers the proxy may read through to merge two requests into one.
    max_gap: int = Field(default=0, ge=0)
    # Device timeout: how long the proxy waits for the device to answer one request before retrying.
    timeout: float = Field(default=3.0, gt=0)
    retries: int = Field(default=3, ge=0)
    # How long to wait for the proxy's reply to a read or write. Must exceed the device timeout: behind a shared
    # gateway a request queues until the other units' requests (including their timeout-and-retry cycles) finish.
    # Defaults to three full timeout-and-retry cycles, and at least 30 seconds.
    reply_timeout: float | None = Field(default=None, gt=0)
    # How long to wait for the proxy process to start and register before declaring setup failed.
    registration_timeout: float = Field(default=30.0, gt=0)
    # Serial settings.
    baudrate: int = Field(default=9600, validation_alias=AliasChoices('baudrate', 'baud_rate'))
    bytesize: int = Field(default=8, ge=5, le=8)
    parity: Parity = Field(default=Parity.none)
    stopbits: StopBits = Field(default=StopBits.one, validation_alias=AliasChoices('stopbits', 'stop_bits'))
    # All Modbus devices share one proxy process unless a group is named here.
    proxy_group: str | None = None

    @field_validator('addressing', mode='before')
    @classmethod
    def _normalize_addressing(cls, v):
        v = _lower_or_none(v)
        return 'offset' if v in (None, 'exact') else v

    @field_validator('parity', 'word_order', 'transport_protocol', mode='before')
    @classmethod
    def _lower(cls, v):
        return _lower_or_none(v) if isinstance(v, str) else v

    @property
    def resolved_reply_timeout(self) -> float:
        if self.reply_timeout is not None:
            return self.reply_timeout
        return max(30.0, 3 * self.timeout * (self.retries + 1))

    @property
    def resolved_port(self) -> int:
        if self.port is not None:
            return self.port
        return 802 if self.transport_protocol is TransportProtocol.tls else 502

    def device_fields(self) -> dict:
        """The fields every proxy message uses to identify this device's client."""
        fields = {'device_address': self.device_address, 'device_type': self.transport_protocol.value}
        if self.transport_protocol is not TransportProtocol.serial:
            fields['port'] = self.resolved_port
        return fields

    def client_options(self) -> dict:
        """pymodbus client settings for REGISTER_DEVICE."""
        options = {'timeout': self.timeout, 'retries': self.retries}
        if self.transport_protocol is TransportProtocol.serial:
            options.update(baudrate=self.baudrate, bytesize=self.bytesize, parity=self.parity.pymodbus,
                           stopbits=self.stopbits.value)
        return options

    def proxy_key(self) -> tuple:
        """Selects the proxy process. Constant by default so all Modbus devices share one."""
        return ('modbus',) if self.proxy_group is None else ('modbus', self.proxy_group)
