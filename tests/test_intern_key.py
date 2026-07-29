"""Unit tests for intern_key.py lifecycle and helpers."""

import os
import shutil
from unittest.mock import patch

import pytest

import en_de_coder.intern_key as ik_mod
from en_de_coder.intern_key import (
    _derive_storage_key,
    _encrypt_key,
    _decrypt_key,
    is_initialized,
    initialize,
    load_intern_key,
    get_intern_key,
    export_key,
    import_key,
    regenerate_key,
    delete_key,
    NotInitializedError,
    HardwareMismatchError,
)

_real_get_key_dir = ik_mod._get_key_dir


@pytest.fixture(autouse=True)
def isolated_key_env(tmp_dir, monkeypatch):
    """Redirect key storage to a temp directory for test isolation."""
    fake_key_dir = os.path.join(tmp_dir, "key_storage")
    monkeypatch.setattr(ik_mod, "_get_key_dir", lambda: fake_key_dir)
    monkeypatch.setattr(ik_mod, "_get_key_file", lambda: os.path.join(fake_key_dir, ".sys.dat"))
    return fake_key_dir


@pytest.fixture
def initialized_key(isolated_key_env):
    """Initialize a key and return the key dir path."""
    initialize()
    return isolated_key_env


class TestGetKeyDir:
    def test_returns_path_containing_en_de_coder(self):
        d = _real_get_key_dir()
        assert "en_de_coder" in d

    def test_returns_absolute_path(self):
        assert os.path.isabs(_real_get_key_dir())


class TestGetKeyFile:
    def test_ends_with_sys_dat(self):
        assert ik_mod._get_key_file().endswith(".sys.dat")

    def test_inside_key_dir(self):
        real_key_dir = _real_get_key_dir()
        real_key_file = os.path.join(real_key_dir, ".sys.dat")
        assert real_key_file.startswith(real_key_dir)


class TestDeriveStorageKey:
    def test_returns_32_bytes(self):
        key = _derive_storage_key("abcdef1234567890abcdef1234567890")
        assert len(key) == 32

    def test_deterministic(self):
        hw_id = "abcdef1234567890abcdef1234567890"
        k1 = _derive_storage_key(hw_id)
        k2 = _derive_storage_key(hw_id)
        assert k1 == k2

    def test_different_hardware_id_different_key(self):
        k1 = _derive_storage_key("0000000000000000000000000000000a")
        k2 = _derive_storage_key("0000000000000000000000000000000b")
        assert k1 != k2


class TestEncryptDecryptKey:
    def test_roundtrip(self):
        data = os.urandom(32)
        hw_id = "abcdef1234567890" * 4
        encrypted = _encrypt_key(data, hw_id)
        decrypted = _decrypt_key(encrypted, hw_id)
        assert decrypted == data

    def test_wrong_hardware_id_fails(self):
        data = os.urandom(32)
        hw_id = "abcdef1234567890" * 4
        encrypted = _encrypt_key(data, hw_id)
        with pytest.raises(Exception):
            _decrypt_key(encrypted, "0000000000000000" * 4)

    def test_encrypted_is_different_from_original(self):
        data = os.urandom(32)
        encrypted = _encrypt_key(data, "abcdef1234567890" * 4)
        assert encrypted != data


class TestIsInitialized:
    def test_false_initially(self, isolated_key_env):
        assert is_initialized() is False

    def test_true_after_initialize(self, initialized_key):
        assert is_initialized() is True


class TestInitialize:
    def test_creates_key_file(self, isolated_key_env):
        initialize()
        assert is_initialized()

    def test_returns_short_hardware_id(self, isolated_key_env):
        result = initialize()
        assert isinstance(result, str)
        assert len(result) == 16

    def test_can_load_key_after_init(self, isolated_key_env):
        initialize()
        key = load_intern_key()
        assert isinstance(key, bytes)
        assert len(key) == 32


class TestLoadInternKey:
    def test_raises_not_initialized(self, isolated_key_env):
        with pytest.raises(NotInitializedError):
            load_intern_key()

    def test_returns_32_bytes(self, initialized_key):
        key = load_intern_key()
        assert len(key) == 32

    def test_loads_same_key_each_time(self, initialized_key):
        k1 = load_intern_key()
        k2 = load_intern_key()
        assert k1 == k2


class TestGetInternKey:
    def test_delegates_to_load(self, initialized_key):
        key = get_intern_key()
        assert isinstance(key, bytes)
        assert len(key) == 32


class TestExportKey:
    def test_exports_file(self, initialized_key, tmp_dir):
        out = os.path.join(tmp_dir, "exported.key")
        export_key(out)
        assert os.path.isfile(out)
        assert os.path.getsize(out) > 0

    def test_raises_not_initialized(self, isolated_key_env, tmp_dir):
        with pytest.raises(NotInitializedError):
            export_key(os.path.join(tmp_dir, "nope.key"))


class TestImportKey:
    def test_imports_and_loads(self, isolated_key_env, tmp_dir):
        initialize()
        exported = os.path.join(tmp_dir, "exported.key")
        export_key(exported)

        delete_key()
        assert not is_initialized()

        import_key(exported)
        assert is_initialized()
        key = load_intern_key()
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_raises_file_not_found(self, isolated_key_env, tmp_dir):
        with pytest.raises(FileNotFoundError):
            import_key(os.path.join(tmp_dir, "nope.key"))


class TestRegenerateKey:
    def test_creates_new_key(self, initialized_key):
        old_key = load_intern_key()
        regenerate_key()
        new_key = load_intern_key()
        assert isinstance(new_key, bytes)
        assert len(new_key) == 32

    def test_returns_short_hardware_id(self, initialized_key):
        result = regenerate_key()
        assert isinstance(result, str)
        assert len(result) == 16


class TestDeleteKey:
    def test_removes_key_file(self, initialized_key):
        assert is_initialized()
        delete_key()
        assert not is_initialized()

    def test_no_error_when_not_initialized(self, isolated_key_env):
        delete_key()
        assert not is_initialized()
