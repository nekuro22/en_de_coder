"""Tests for the en_de_coder CLI interface."""

import os
import sys
import tempfile
import shutil

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from en_de_coder.cli import build_parser, main


def test_parser_encrypt():
    """Test encrypt command parsing."""
    parser = build_parser()
    args = parser.parse_args(["encrypt", "myfile.txt", "-p", "testpass123!", "-a", "aes-gcm"])
    assert args.command == "encrypt"
    assert args.input == "myfile.txt"
    assert args.password == "testpass123!"
    assert args.algorithm == "aes-gcm"


def test_parser_encrypt_aliases():
    """Test encrypt alias."""
    parser = build_parser()
    args = parser.parse_args(["e", "myfile.txt"])
    assert args.command == "e"


def test_parser_decrypt():
    """Test decrypt command parsing."""
    parser = build_parser()
    args = parser.parse_args(["decrypt", "myfile.txt.enc", "-p", "testpass123!"])
    assert args.command == "decrypt"
    assert args.input == "myfile.txt.enc"


def test_parser_info():
    """Test info command parsing."""
    parser = build_parser()
    args = parser.parse_args(["info", "myfile.txt.enc"])
    assert args.command == "info"
    assert args.input == "myfile.txt.enc"


def test_parser_generate_password():
    """Test generate-password command parsing."""
    parser = build_parser()
    args = parser.parse_args(["generate-password", "-l", "32"])
    assert args.command == "generate-password"
    assert args.length == 32


def test_encrypt_decrypt_roundtrip():
    """Test full encrypt/decrypt roundtrip."""
    tmpdir = tempfile.mkdtemp()
    try:
        test_file = os.path.join(tmpdir, "test_input.txt")
        encrypted_file = os.path.join(tmpdir, "test_input.txt.enc")
        decrypted_file = os.path.join(tmpdir, "test_output.txt")

        test_content = b"Hello World! This is a secret test content.\x00\xFF"

        with open(test_file, "wb") as f:
            f.write(test_content)

        # Encrypt
        main(["encrypt", test_file, "-p", "TestPassword123!", "-o", encrypted_file, "-f"])

        assert os.path.exists(encrypted_file)
        enc_size = os.path.getsize(encrypted_file)
        assert enc_size > len(test_content)

        # Decrypt
        main(["decrypt", encrypted_file, "-p", "TestPassword123!", "-o", decrypted_file, "-f"])

        assert os.path.exists(decrypted_file)
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()
        assert decrypted_content == test_content

        print("  Roundtrip test PASSED")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_encrypt_all_algorithms():
    """Test encryption with all algorithms."""
    tmpdir = tempfile.mkdtemp()
    try:
        test_file = os.path.join(tmpdir, "algo_test.txt")
        test_content = b"Algorithm test content"

        with open(test_file, "wb") as f:
            f.write(test_content)

        for algo in ["aes-gcm", "chacha20", "fernet"]:
            test_file_algo = os.path.join(tmpdir, f"algo_test_{algo}.txt")
            with open(test_file_algo, "wb") as f:
                f.write(test_content)

            encrypted_file = os.path.join(tmpdir, f"test.{algo}.enc")
            decrypted_file = os.path.join(tmpdir, f"test.{algo}.dec.txt")

            main(["encrypt", test_file_algo, "-p", "TestPassword123!", "-a", algo,
                  "-o", encrypted_file, "-f"])
            assert os.path.exists(encrypted_file)

            main(["decrypt", encrypted_file, "-p", "TestPassword123!",
                  "-o", decrypted_file, "-f"])

            with open(decrypted_file, "rb") as f:
                assert f.read() == test_content

        print("  All algorithms test PASSED")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_info_command():
    """Test info command on encrypted file."""
    from en_de_coder.crypto import FileEncryptor

    tmpdir = tempfile.mkdtemp()
    try:
        test_file = os.path.join(tmpdir, "info_test.txt")
        encrypted_file = os.path.join(tmpdir, "info_test.txt.enc")

        with open(test_file, "wb") as f:
            f.write(b"Info test")

        encryptor = FileEncryptor()
        encryptor.encrypt_file(test_file, encrypted_file, "TestPassword123!", "aes-gcm")

        # Info should not crash
        main(["info", encrypted_file])

        print("  Info command test PASSED")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_folder_encrypt_decrypt():
    """Test folder encryption/decryption."""
    tmpdir = tempfile.mkdtemp()
    try:
        # Create test folder
        folder = os.path.join(tmpdir, "test_folder")
        os.makedirs(folder)
        with open(os.path.join(folder, "file1.txt"), "w") as f:
            f.write("File 1 content")
        os.makedirs(os.path.join(folder, "subdir"))
        with open(os.path.join(folder, "subdir", "file2.txt"), "w") as f:
            f.write("File 2 content")

        encrypted_file = os.path.join(tmpdir, "test_folder.enc")
        output_folder = os.path.join(tmpdir, "restored")

        # Encrypt
        main(["encrypt", folder, "-p", "FolderPass123!", "-o", encrypted_file, "-f"])
        assert os.path.exists(encrypted_file)

        # Decrypt
        os.makedirs(output_folder, exist_ok=True)
        main(["decrypt", encrypted_file, "-p", "FolderPass123!", "-o", output_folder, "-f"])

        assert os.path.exists(os.path.join(output_folder, "file1.txt"))
        assert os.path.exists(os.path.join(output_folder, "subdir", "file2.txt"))

        print("  Folder encrypt/decrypt test PASSED")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_ttl_encrypt_decrypt():
    """Test time-lock feature."""
    import time
    from en_de_coder.crypto import FileEncryptor

    tmpdir = tempfile.mkdtemp()
    try:
        test_file = os.path.join(tmpdir, "ttl_test.txt")
        enc_file = os.path.join(tmpdir, "ttl_test.txt.enc")
        dec_file = os.path.join(tmpdir, "ttl_test_dec.txt")

        with open(test_file, "wb") as f:
            f.write(b"TTL test content")

        enc = FileEncryptor()

        # Encrypt with 1s TTL
        enc.encrypt_file(test_file, enc_file, "TTLPass123!", "aes-gcm", ttl=1)

        # Try to decrypt without password (should fail - locked)
        try:
            enc.decrypt_file(enc_file, dec_file, None)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "time-locked" in str(e).lower()

        # Decrypt with password (should work)
        enc.decrypt_file(enc_file, dec_file, "TTLPass123!")
        with open(dec_file, "rb") as f:
            assert f.read() == b"TTL test content"

        # Wait for TTL to expire
        time.sleep(2)

        # Decrypt without password (should work now)
        dec_file2 = os.path.join(tmpdir, "ttl_test_dec2.txt")
        enc.decrypt_file(enc_file, dec_file2, None)
        with open(dec_file2, "rb") as f:
            assert f.read() == b"TTL test content"

        print("  TTL encrypt/decrypt test PASSED")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_ttl_cli():
    """Test TTL via CLI."""
    import time

    tmpdir = tempfile.mkdtemp()
    try:
        test_file = os.path.join(tmpdir, "ttl_cli.txt")
        enc_file = os.path.join(tmpdir, "ttl_cli.txt.enc")

        with open(test_file, "w") as f:
            f.write("TTL CLI test")

        # Encrypt with 1s TTL
        main(["encrypt", test_file, "-p", "TTLcli123!", "-t", "1s", "-o", enc_file, "-f"])

        # Info should show LOCKED
        # (we can't easily capture stdout here, but it shouldn't crash)
        main(["info", enc_file])

        print("  TTL CLI test PASSED")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_parser_encrypt_with_time():
    """Test encrypt command with -t argument."""
    parser = build_parser()
    args = parser.parse_args(["encrypt", "file.txt", "-p", "pass123!", "-t", "5m"])
    assert args.time == "5m"


if __name__ == "__main__":
    print("Running CLI tests...")
    print("=" * 50)
    test_parser_encrypt()
    test_parser_encrypt_aliases()
    test_parser_decrypt()
    test_parser_info()
    test_parser_generate_password()
    test_parser_encrypt_with_time()
    test_encrypt_decrypt_roundtrip()
    test_encrypt_all_algorithms()
    test_info_command()
    test_folder_encrypt_decrypt()
    test_ttl_encrypt_decrypt()
    test_ttl_cli()
    print("=" * 50)
    print("All CLI tests PASSED!")
