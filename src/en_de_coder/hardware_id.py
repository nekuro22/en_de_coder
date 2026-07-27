"""Hardware identification module - generates a device-specific fingerprint.

The hardware ID is derived from CPU, motherboard, disk, and network identifiers.
It is used to bind the internal key to a specific device.
"""

import hashlib
import os
import platform
import subprocess
import uuid


def _get_cpu_id() -> str:
    """Get CPU identifier."""
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(
                ["wmic", "cpu", "get", "ProcessorId"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and l.strip() != "ProcessorId"]
            if lines:
                return lines[0]
        elif system == "Linux":
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "Serial" in line or "model name" in line:
                        return line.split(":")[-1].strip()
        elif system == "Darwin":
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown_cpu"


def _get_motherboard_id() -> str:
    """Get motherboard serial number."""
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(
                ["wmic", "baseboard", "get", "SerialNumber"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and l.strip() != "SerialNumber"]
            if lines:
                return lines[0]
        elif system == "Linux":
            paths = [
                "/sys/class/dmi/id/board_serial",
                "/sys/class/dmi/id/product_serial",
            ]
            for path in paths:
                if os.path.exists(path):
                    with open(path) as f:
                        return f.read().strip()
    except Exception:
        pass
    return "unknown_mobo"


def _get_disk_serial() -> str:
    """Get primary disk serial number."""
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(
                ["wmic", "diskdrive", "get", "SerialNumber"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and l.strip() != "SerialNumber"]
            if lines:
                return lines[0]
        elif system == "Linux":
            result = subprocess.run(
                ["lsblk", "-dno", "SERIAL", "/dev/sda"],
                capture_output=True, text=True, timeout=5,
            )
            serial = result.stdout.strip()
            if serial:
                return serial
    except Exception:
        pass
    return "unknown_disk"


def _get_mac_address() -> str:
    """Get MAC address as fallback identifier."""
    mac = uuid.getnode()
    return ":".join(f"{(mac >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6)))


def get_hardware_id() -> str:
    """Generate a stable hardware fingerprint (SHA-256 hash).

    Combines CPU, motherboard, disk, and MAC identifiers into a single
    deterministic hash that changes when hardware changes.

    Returns:
        64-character hex string (SHA-256 hash).
    """
    components = [
        _get_cpu_id(),
        _get_motherboard_id(),
        _get_disk_serial(),
        _get_mac_address(),
    ]

    material = "|".join(components).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def get_short_hardware_id() -> str:
    """Return a shortened 16-character hardware ID for display purposes."""
    return get_hardware_id()[:16]
