"""Test configuration for en_de_coder tests."""

import os
import sys
import shutil
import tempfile

import pytest

# Ensure src is on the path for test discovery
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from en_de_coder.crypto import EncryptionBackend


@pytest.fixture(autouse=True)
def clean_lockout():
    """Reset brute-force lockout state before and after every test."""
    EncryptionBackend._failed_attempts.clear()
    EncryptionBackend._lockout_until.clear()
    yield
    EncryptionBackend._failed_attempts.clear()
    EncryptionBackend._lockout_until.clear()


@pytest.fixture
def tmp_dir():
    """Create a temporary directory with automatic cleanup."""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def sample_file(tmp_dir):
    """Create a sample file for testing and return its path."""
    path = os.path.join(tmp_dir, "test_input.txt")
    with open(path, "wb") as f:
        f.write(b"Test content 123!@#$")
    return path
