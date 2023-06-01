"""
Infrastructure Agent: NRPE packet handler
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import abc
import binascii
import dataclasses
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent.objects import Result


class NRPEPacketException(Exception):
    pass


class AbstractPacket(metaclass=abc.ABCMeta):
    """Base class for packet types"""
    MAX_BUFFER_SIZE: int

    buffer: bytes

    # Request only attributes to be decoded from received struct
    check_name: str = None
    check_arguments: list[str] = None

    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, byte_object: bytes) -> AbstractPacket:
        pass  # pragma: no cover

    @classmethod
    @abc.abstractmethod
    def create_packets_from_result(cls, result: Result, allow_multi_packet_response: bool) -> list:
        pass  # pragma: no cover


@dataclasses.dataclass
class NRPEPacketV2(AbstractPacket):
    """
    Represents an NRPE v2 packet sent via an NRPE client.
    https://github.com/stockholmuniversity/Nagios-NRPE/blob/master/share/protocol-nrpe.md
    """
    NRPE_REQUEST_TYPE = 1
    NRPE_RESPONSE_TYPE = 2
    # Opsview specific modification to the NRPEv2 protocol
    # Note: Requires an Opsview modified check_nrpe client
    NRPE_RESPONSE_PACKET_WITH_MORE_TYPE = 3

    MAX_BUFFER_SIZE = 1024  # bytes
    MAX_BUFFER_STRING_SIZE = MAX_BUFFER_SIZE - 1  # Make room for the terminating \x00

    VERSION = 2

    ARG_SPLIT_CHAR = '!'

    # ! indicates big-endian network byte order
    STRUCT_FORMAT = '!hhIh1024sh'

    packet_version: int  # int16_t    h
    packet_type: int     # int16_t    h
    crc32_value: int     # u_int32_t  I
    result_code: int     # int16_t    h
    buffer: bytes        # char[1024] 1024s

    # check_nrpe's 'packet_struct' struct looks like it should be 1034 bytes long,
    # but because of C's structure padding it is actually 1036 (1034 + (1034 % 4))
    # the "randomly" generated padding bytes are used in check_nrpe to calculate the CRC32
    # value of the packet, and so we need to hold on to them for when _we_ calculate the CRC32
    # to validate the packets contents.
    # for response packets we keep this as 0 (b'\x00\x00').
    _padding: int = 0    # struct padding h

    def __post_init__(self):
        self.buffer = self.buffer.split(b'\x00')[0]
        if self.packet_type == self.NRPE_REQUEST_TYPE:
            self._parse_request_buffer()

    def _parse_request_buffer(self):
        """Parses the buffer """
        command_parts = self.buffer.decode('utf-8').split(self.ARG_SPLIT_CHAR)
        self.check_name = command_parts[0]
        # This looks a bit like it might fail with an IndexError if len(command_parts) == 1
        # but Python list slicing returns an empty list even if the index starts after the
        # end of the list!
        self.check_arguments = command_parts[1:]

    def calc_crc32_value(self) -> int:
        """Calculates the CRC32 checksum of the packet and returns it"""
        packet = struct.pack(
            self.STRUCT_FORMAT,
            self.packet_version, self.packet_type, 0, self.result_code, self.buffer, self._padding
        )
        return binascii.crc32(packet)

    @classmethod
    def from_bytes(cls, byte_object: bytes) -> NRPEPacketV2:
        """
        Creates a NRPEPacketV2 object from a bytes object.
        Raises an NRPEPacketException if something goes wrong unpacking the bytes object.
        """
        try:
            # Unpack received struct into NRPEPacketV2 object
            received_object = cls(*struct.unpack(cls.STRUCT_FORMAT, byte_object))
            # Validate that received struct checksum matches packet contents
            real_checksum = received_object.calc_crc32_value()
            if real_checksum != received_object.crc32_value:
                raise NRPEPacketException(
                    f"Invalid NRPEv2 packet - checksum error ({real_checksum} != {received_object.crc32_value})"
                )
            return received_object
        except NRPEPacketException as ex:
            raise ex
        except Exception as ex:
            raise NRPEPacketException(f"Invalid NRPEv2 packet ({ex.__class__.__name__} - {str(ex)})") from ex

    def to_bytes(self) -> bytes:
        """
        Creates a bytes object from the NRPEPacketV2 object, calculating 'crc32_value' if it has not been done yet.
        """
        if not self.crc32_value:
            self.crc32_value = self.calc_crc32_value()

        return struct.pack(
            self.STRUCT_FORMAT,
            self.packet_version, self.packet_type, self.crc32_value, self.result_code, self.buffer, self._padding
        )

    @classmethod
    def create_packets_from_result(cls, result: Result, allow_multi_packet_response: bool) -> list[NRPEPacketV2]:
        stdout = result.stdout.encode('utf-8')
        stdout_length = len(stdout)
        if (stdout_length > cls.MAX_BUFFER_STRING_SIZE) and allow_multi_packet_response:
            # Split up stdout into MAX_BUFFER_SIZE - 1 chunks
            stdout_parts = [
                stdout[i: i + cls.MAX_BUFFER_STRING_SIZE] for i in range(0, stdout_length, cls.MAX_BUFFER_STRING_SIZE)
            ]
            packets = [
                cls(
                    packet_version=cls.VERSION,
                    packet_type=cls.NRPE_RESPONSE_PACKET_WITH_MORE_TYPE,  # A real CRC will be calculated later
                    crc32_value=0,
                    result_code=result.rc,
                    buffer=stdout_part
                ) for stdout_part in stdout_parts
            ]
            # Set the last packet's type to NRPE_RESPONSE_TYPE so the client is
            # aware the series of response packets has come to an end
            packets[-1].packet_type = cls.NRPE_RESPONSE_TYPE
            return packets

        return [
            cls(
                packet_version=cls.VERSION,
                packet_type=cls.NRPE_RESPONSE_TYPE,
                crc32_value=0,  # A real CRC will be calculated later
                result_code=result.rc,
                buffer=result.stdout.encode('utf-8')[:cls.MAX_BUFFER_STRING_SIZE]
            )
        ]
