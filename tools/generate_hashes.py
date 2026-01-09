#!/usr/bin/env python3
"""
Hash Manifest Generator for CobaltGraph
Generates PACKAGE_HASHES dictionary for embedding in launcher

Usage:
    python3 tools/generate_hashes.py > hashes_output.txt
    # Then copy PACKAGE_HASHES dict into cobaltgraph launcher at line ~106
"""

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


def get_wheel_hash(package_name, version):
    """
    Get SHA256 hash of package wheel from pip cache.

    Args:
        package_name (str): Package name (e.g., 'numpy')
        version (str): Version spec (e.g., '2.3.5')

    Returns:
        str: SHA256 hash in format 'sha256:...' or None if failed
    """
    temp_dir = tempfile.mkdtemp()

    try:
        # Download wheel without installing
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'download',
             f'{package_name}=={version}', '--no-deps', '--dest', temp_dir],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"# Warning: Could not download {package_name}=={version}", file=sys.stderr)
            return None

        # Find downloaded wheel or tar.gz
        temp_path = Path(temp_dir)
        wheel_files = list(temp_path.glob(f'{package_name}*.whl'))
        if not wheel_files:
            wheel_files = list(temp_path.glob(f'{package_name}*.tar.gz'))

        if not wheel_files:
            print(f"# Warning: No package file found for {package_name}", file=sys.stderr)
            return None

        wheel_path = wheel_files[0]

        # Compute SHA256
        sha256 = hashlib.sha256()
        with open(wheel_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)

        hash_value = sha256.hexdigest()

        # Clean up
        wheel_path.unlink()

        return f"sha256:{hash_value}"

    except Exception as e:
        print(f"# Error getting hash for {package_name}=={version}: {e}", file=sys.stderr)
        return None
    finally:
        # Clean up temp directory
        try:
            Path(temp_dir).rmdir()
        except:
            pass


def generate_manifest():
    """Generate PACKAGE_HASHES dictionary from requirements.txt"""

    requirements_path = Path(__file__).parent.parent / 'requirements.txt'

    if not requirements_path.exists():
        print(f"Error: requirements.txt not found at {requirements_path}", file=sys.stderr)
        sys.exit(1)

    print("# ============================================================================")
    print("# PACKAGE HASH MANIFEST - Auto-generated")
    print("# ============================================================================")
    print("# This manifest provides SHA256 hashes for package integrity verification.")
    print("# ")
    print("# INSTRUCTIONS:")
    print("# 1. Copy this entire PACKAGE_HASHES dict")
    print("# 2. Paste into cobaltgraph launcher (replace existing PACKAGE_HASHES)")
    print("# 3. Update _manifest_version to today's date")
    print("# 4. Test: ./cobaltgraph --health")
    print("# ============================================================================")
    print()
    print("PACKAGE_HASHES = {")
    print("    # Manifest version - update to today's date")
    print("    '_manifest_version': '2026-01-08',")
    print()
    print("    # Critical packages (required for operation)")
    print("    # Format: 'package-name': ['sha256:hash1', 'sha256:hash2', ...]")
    print("    # Multiple hashes support version ranges (numpy>=2.3.5 allows 2.3.5, 2.3.6, etc.)")
    print()

    # Parse requirements.txt
    import re
    package_regex = re.compile(r'^([a-zA-Z0-9\-_]+)\s*([><=!]+)\s*([0-9\.]+)')

    current_section = 'CRITICAL'

    with open(requirements_path, 'r') as f:
        for line in f:
            line_stripped = line.strip()

            # Detect section headers
            if line_stripped.startswith('#'):
                upper_line = line_stripped.upper()
                if 'DEVELOPMENT' in upper_line or 'OPTIONAL' in upper_line or 'VISUALIZATION' in upper_line:
                    current_section = 'OPTIONAL'
                    print(f"\n    # {line_stripped[2:].strip()}")
                    continue
                # Pass through comment lines
                if len(line_stripped) > 2:
                    print(f"    # {line_stripped[2:].strip()}")
                continue

            # Skip blank lines
            if not line_stripped:
                print()
                continue

            # Parse package specification
            match = package_regex.match(line_stripped)
            if match:
                package = match.group(1)
                operator = match.group(2)
                version = match.group(3)

                # Only generate hashes for minimum versions (>=)
                if operator == '>=':
                    print(f"    # Generating hash for {package}=={version}...", file=sys.stderr)
                    hash_value = get_wheel_hash(package, version)

                    if hash_value:
                        print(f"    '{package}': ['{hash_value}'],  # {version}")
                    else:
                        print(f"    '{package}': [],  # {version} - HASH GENERATION FAILED")
                else:
                    # For exact versions, use that version
                    print(f"    # Generating hash for {package}=={version}...", file=sys.stderr)
                    hash_value = get_wheel_hash(package, version)

                    if hash_value:
                        print(f"    '{package}': ['{hash_value}'],  # {version}")
                    else:
                        print(f"    '{package}': [],  # {version} - HASH GENERATION FAILED")

    print("}")
    print()
    print("# ============================================================================")
    print("# Generated successfully!")
    print("# Next steps:")
    print("# 1. Review the output above")
    print("# 2. Copy PACKAGE_HASHES dict into cobaltgraph launcher")
    print("# 3. Update _manifest_version to current date")
    print("# 4. Run: ./cobaltgraph --health")
    print("# ============================================================================")


if __name__ == '__main__':
    print("# CobaltGraph Hash Manifest Generator", file=sys.stderr)
    print("# Starting hash generation (this may take a few minutes)...", file=sys.stderr)
    print("#", file=sys.stderr)

    try:
        generate_manifest()
    except KeyboardInterrupt:
        print("\n# Hash generation cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n# Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
