"""Cross-platform build script for en_de_coder.

Usage:
    python build.py

Produces a single executable in dist/ for the current platform.
"""

import os
import platform
import subprocess
import sys


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    spec_file = os.path.join(root, "en_de_coder.spec")
    use_clean = "--clean" in sys.argv

    if not os.path.isfile(spec_file):
        print(f"Error: {spec_file} not found.", file=sys.stderr)
        sys.exit(1)

    print(f"Platform: {platform.system()} ({platform.machine()})")
    print(f"Python:   {sys.version}")
    print()

    cmd = [sys.executable, "-m", "PyInstaller", spec_file, "--noconfirm"]
    if use_clean:
        cmd.append("--clean")
    print(f"Running: {' '.join(cmd)}")
    print()

    result = subprocess.run(cmd, cwd=root)

    if result.returncode != 0:
        print(f"\nBuild failed with exit code {result.returncode}.", file=sys.stderr)
        sys.exit(result.returncode)

    dist_dir = os.path.join(root, "dist")
    if platform.system() == "Windows":
        exe = os.path.join(dist_dir, "en_de_coder.exe")
    else:
        exe = os.path.join(dist_dir, "en_de_coder")

    if os.path.isfile(exe):
        size_mb = os.path.getsize(exe) / (1024 * 1024)
        print()
        print(f"Build successful: {exe}")
        print(f"Size: {size_mb:.1f} MB")
    else:
        print(f"\nWarning: Expected output not found at {exe}", file=sys.stderr)


if __name__ == "__main__":
    main()
