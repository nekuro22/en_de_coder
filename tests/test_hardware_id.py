"""Unit tests for hardware_id.py."""

import hashlib
import re

from en_de_coder.hardware_id import (
    get_hardware_id,
    get_short_hardware_id,
    _get_mac_address,
    _get_cpu_id,
    _get_motherboard_id,
    _get_disk_serial,
)


class TestGetHardwareId:
    def test_returns_64_char_hex(self):
        hw_id = get_hardware_id()
        assert len(hw_id) == 64
        assert re.fullmatch(r"[0-9a-f]{64}", hw_id)

    def test_deterministic(self):
        id1 = get_hardware_id()
        id2 = get_hardware_id()
        assert id1 == id2

    def test_is_sha256_hash(self):
        hw_id = get_hardware_id()
        assert int(hw_id, 16) < 2**256


class TestGetShortHardwareId:
    def test_returns_16_chars(self):
        short = get_short_hardware_id()
        assert len(short) == 16

    def test_is_prefix_of_full_id(self):
        full = get_hardware_id()
        short = get_short_hardware_id()
        assert full.startswith(short)


class TestGetMacAddress:
    def test_valid_mac_format(self):
        mac = _get_mac_address()
        assert re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac)


class TestFallbackValues:
    def test_cpu_id_returns_string(self):
        result = _get_cpu_id()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_motherboard_id_returns_string(self):
        result = _get_motherboard_id()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_disk_serial_returns_string(self):
        result = _get_disk_serial()
        assert isinstance(result, str)
        assert len(result) > 0
