"""
CLI interface for en_de_coder.

Usage:
    enc encrypt <input> [options]
    enc decrypt <input> [options]
    enc info <file.encrypted>
    enc register
    enc generate-password
"""

import argparse
import getpass
import os
import secrets
import string
import sys

from en_de_coder import __version__
from en_de_coder.crypto import ALGO_MAP_CLI_TO_INTERNAL, FileEncryptor, parse_duration, format_duration


def _confirm_overwrite(path: str) -> bool:
    """Ask user to confirm overwriting an existing file."""
    if os.path.exists(path):
        try:
            answer = input(f"Overwrite existing file '{path}'? [y/N] ").strip().lower()
            return answer in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False
    return True


def _get_password(args: argparse.Namespace, confirm: bool = False) -> str:
    """Get password from args or interactively."""
    password = getattr(args, "password", None)
    if password:
        return password

    password = getpass.getpass("Enter password: ")
    if not password:
        print("Error: Password cannot be empty.", file=sys.stderr)
        sys.exit(1)

    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    return password


def cmd_encrypt(args: argparse.Namespace) -> None:
    """Encrypt a file or folder."""
    input_path = args.input

    if not os.path.exists(input_path):
        print(f"Error: Path not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    password = _get_password(args, confirm=True)

    algorithm = args.algorithm or "aes-gcm"
    if algorithm not in ALGO_MAP_CLI_TO_INTERNAL:
        print(
            f"Error: Unknown algorithm '{algorithm}'. "
            f"Available: {', '.join(ALGO_MAP_CLI_TO_INTERNAL.keys())}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Parse TTL
    ttl = None
    if args.time:
        try:
            ttl = parse_duration(args.time)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        output_path = input_path + ".encrypted"

    if not args.force and not _confirm_overwrite(output_path):
        print("Aborted.", file=sys.stderr)
        sys.exit(1)

    encryptor = FileEncryptor()

    try:
        if os.path.isfile(input_path):
            print(f"Encrypting file: {input_path}")
            encryptor.encrypt_file(input_path, output_path, password, algorithm, ttl=ttl)
        elif os.path.isdir(input_path):
            print(f"Encrypting folder: {input_path}")
            encryptor.encrypt_folder(input_path, output_path, password, algorithm, ttl=ttl)
        else:
            print(f"Error: '{input_path}' is not a file or folder.", file=sys.stderr)
            sys.exit(1)

        size = os.path.getsize(output_path)
        print(f"{input_path} -> {output_path} ({size:,} bytes)")
        print(f"Algorithm: {algorithm}")
        if ttl is not None:
            print(f"Time-lock:  {args.time} (expires in {format_duration(ttl)})")

        # Delete original after successful encryption
        if args.delete_original:
            import shutil
            if os.path.isfile(input_path):
                os.remove(input_path)
                print(f"Deleted:   {input_path}")
            elif os.path.isdir(input_path):
                shutil.rmtree(input_path)
                print(f"Deleted:   {input_path}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_decrypt(args: argparse.Namespace) -> None:
    """Decrypt a file or folder."""
    input_path = args.input

    if not os.path.isfile(input_path):
        print(f"Error: File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    file_size = os.path.getsize(input_path)
    if file_size < 50:
        print("Error: File too small - probably not encrypted.", file=sys.stderr)
        sys.exit(1)

    # Check TTL status before asking for password
    encryptor = FileEncryptor()
    try:
        info = encryptor.get_file_info(input_path)
    except Exception as e:
        print(f"Error: Cannot read file: {e}", file=sys.stderr)
        sys.exit(1)

    ttl_status = info.get("ttl_status", "none")
    if ttl_status == "locked":
        remaining = info.get("ttl_remaining", 0)
        print(f"File is time-locked. Expires in {format_duration(remaining)}.")
        if not args.password:
            print("Use -p <password> to decrypt immediately.", file=sys.stderr)
            sys.exit(1)
    elif ttl_status == "expired":
        print("Time-lock expired. Password is not required.")

    # Get password (optional if TTL expired)
    password = None
    if ttl_status != "expired":
        password = _get_password(args)
    elif args.password:
        password = args.password

    is_folder = info["is_folder"]
    original_name = info["original_name"]

    # Determine output path
    if args.output:
        output_path = args.output
    elif is_folder:
        output_path = os.path.join(
            os.path.dirname(input_path) or ".", original_name
        )
    else:
        output_path = os.path.join(
            os.path.dirname(input_path) or ".", original_name
        )

    if not args.force and not _confirm_overwrite(output_path):
        print("Aborted.", file=sys.stderr)
        sys.exit(1)

    try:
        print(f"Decrypting: {input_path}")
        if is_folder:
            os.makedirs(output_path, exist_ok=True)
            encryptor.decrypt_folder(input_path, output_path, password or "")
        else:
            encryptor.decrypt_file(input_path, output_path, password)

        print(f"{input_path} -> {output_path}")
        print(f"Algorithm: {info['algorithm']}")
    except Exception as e:
        print(f"Error: Wrong password or corrupted file. {e}", file=sys.stderr)
        sys.exit(1)


def cmd_info(args: argparse.Namespace) -> None:
    """Show metadata of an encrypted file."""
    input_path = args.input

    if not os.path.isfile(input_path):
        print(f"Error: File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    encryptor = FileEncryptor()

    try:
        info = encryptor.get_file_info(input_path)
    except Exception as e:
        print(f"Error: Cannot read file: {e}", file=sys.stderr)
        sys.exit(1)

    file_type = "Folder" if info["is_folder"] else "File"
    print(f"Algorithm:      {info['algorithm']}")
    print(f"Original name:  {info['original_name']}")
    print(f"Type:           {file_type}")
    print(f"Encrypted size: {info['file_size']:,} bytes")

    ttl_status = info.get("ttl_status", "none")
    if ttl_status == "expired":
        print(f"Time-lock:      EXPIRED (password not required)")
    elif ttl_status == "locked":
        remaining = info.get("ttl_remaining", 0)
        print(f"Time-lock:      LOCKED (expires in {format_duration(remaining)})")
    else:
        print(f"Time-lock:      none")


def cmd_register(args: argparse.Namespace) -> None:
    """Register .encrypted file type for the current platform."""
    from en_de_coder.register import register

    register()


def cmd_generate_password(args: argparse.Namespace) -> None:
    """Generate a secure random password."""
    length = args.length or 16
    if length < 1:
        print("Error: Password length must be at least 1.", file=sys.stderr)
        sys.exit(1)

    characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    password = "".join(secrets.choice(characters) for _ in range(length))

    print(f"Generated password ({length} chars): {password}")
    print()
    print("IMPORTANT: Save this password securely!")
    print("Decryption is impossible without it.")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="enc",
        description="Cross-platform file & folder encryption tool",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # encrypt
    enc = subparsers.add_parser("encrypt", aliases=["e"], help="Encrypt a file or folder")
    enc.add_argument("input", help="File or folder to encrypt")
    enc.add_argument("-p", "--password", help="Password (prompted if omitted)")
    enc.add_argument("-o", "--output", help="Output path (default: input.encrypted)")
    enc.add_argument(
        "-a",
        "--algorithm",
        choices=list(ALGO_MAP_CLI_TO_INTERNAL.keys()),
        default="aes-gcm",
        help="Encryption algorithm (default: aes-gcm)",
    )
    enc.add_argument(
        "-t",
        "--time",
        help="Time-lock duration (e.g. 20s, 5m, 2h, 1d). Password optional after expiry.",
    )
    enc.add_argument("-f", "--force", action="store_true", help="Overwrite without asking")
    enc.add_argument(
        "-x", "--delete-original",
        action="store_true",
        help="Delete original file/folder after successful encryption",
    )

    # decrypt
    dec = subparsers.add_parser("decrypt", aliases=["d"], help="Decrypt a file or folder")
    dec.add_argument("input", help="Encrypted file to decrypt")
    dec.add_argument("-p", "--password", help="Password (prompted if omitted)")
    dec.add_argument("-o", "--output", help="Output path (default: original name)")
    dec.add_argument("-f", "--force", action="store_true", help="Overwrite without asking")

    # info
    info = subparsers.add_parser("info", aliases=["i"], help="Show encrypted file metadata")
    info.add_argument("input", help="Encrypted file to inspect")

    # register
    subparsers.add_parser("register", aliases=["r"], help="Register .encrypted file type")

    # generate-password
    gen = subparsers.add_parser("generate-password", aliases=["g"], help="Generate a secure password")
    gen.add_argument("-l", "--length", type=int, default=16, help="Password length (default: 16)")

    return parser


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    commands = {
        "encrypt": cmd_encrypt,
        "e": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "d": cmd_decrypt,
        "info": cmd_info,
        "i": cmd_info,
        "register": cmd_register,
        "r": cmd_register,
        "generate-password": cmd_generate_password,
        "g": cmd_generate_password,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
