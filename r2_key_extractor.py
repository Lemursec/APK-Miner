#!/usr/bin/env python3
"""
Private Key Extractor from Linux .so Binary
Uses r2pipe to extract RSA/DSS/EC private keys from shared object files
"""

import os
import sys
import subprocess
import re
import r2pipe
from datetime import datetime

# Supported key file sizes for RSA (in bytes)
KEY_SIZES = [32, 48, 66, 512, 1024, 2048, 4096, 8192]

# OpenSSL validation commands
OPENSSL_VALIDATION_COMMANDS = [
    "openssl rsa -in {file} -check -noout",
    "openssl dsa -in {file} -text -noout",
    "openssl ec -in {file} -check -noout",
    "openssl pkey -in {file} -check -noout"
]


def validate_key_with_openssl(key_file_path):
    """
    Validate extracted PEM key using multiple openssl commands.
    Returns True if at least one command validates the key successfully.
    """
    for cmd_template in OPENSSL_VALIDATION_COMMANDS:
        cmd = cmd_template.format(file=key_file_path)
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=False
            )
            # Check for success indicators in output
            output = result.stdout.strip().lower()
            #print(f"DEBUG: {cmd}")
            #print(f"DEBUG: {output}")
            if result.returncode == 0 and (
                "key valid" in output or
                "valid" in output or
                ("RSA" in output and "valid" in output) or
                "DSA" in output and result.returncode == 0
            ):
                print(f"[✓] Validated via: {cmd}")
                return True
        except Exception as e:
            print(f"[!] Error running openssl command: {e}")
            continue

    print("[✗] Key validation failed with all openssl commands")
    return False


def extract_private_keys(binary_path, output_dir=".extracted_keys"):
    """
    Main extraction function using r2pipe to find and extract private keys.
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Initialize r2pipe
    print(f"[*] Opening binary with r2pipe: {binary_path}")
    try:
        r2 = r2pipe.open(binary_path)
    except Exception as e:
        print(f"[!] Error opening binary with r2pipe: {e}")
        return

    print("[*] Analyzing everything aa...")
    r2.cmd('aa')

    print("[*] Analyzing /m (memory mappings) table...")

    # Get memory mappings table
    m_table = r2.cmd('/m~^|')

    # Parse table rows - looking for rows with "Private key" in name
    private_key_rows = []
    lines = m_table.split('\n')

    for line in lines:
        if 'Private key' in line:
            # Parse line to extract address (first column typically)
            parts = line.split()
            if len(parts) >= 2:
                addr = parts[0]
                name = parts[1] if len(parts) > 1 else ""
                private_key_rows.append((addr, name))

    print(f"[*] Found {len(private_key_rows)} memory regions with PRIVATE in name")

    # Process each private key region
    for idx, (address, name) in enumerate(private_key_rows, 1):
        print(f"\n[{idx}/{len(private_key_rows)}] Processing address: {address} (name: {idx})")

        # Determine appropriate file naming
        now = datetime.now()
        timestamp = now.strftime("%Y-%d-%m-%H%M%S")
        str_id = str(idx)
        base_name = re.sub(r'[^a-zA-Z0-9_.]', '_', f"key_{str_id}")
        base_name += "_"+timestamp
        print(f"base_name: {base_name}")

        # Determine size_in_bytes - try to extract from memory mapping info
        # First attempt: try to calculate from size in table row
        size = None
        if len(lines) > 0 and address in lines[idx]:
            # Extract size from the line if available
            size_match = re.search(r'(\d+)\s*bytes', str(lines[idx]))
            if size_match:
                size = int(size_match.group(1))
                print(f"[+] Detected size from table: {size} bytes")

        # If size detection failed, try fallback sizes
        if not size:
            print("[!] Size not determined from table, trying fallback sizes: 32, 48, 66, 512, 1024, 2048, 4096, 8192 bytes")

        # Extract key with appropriate size
        extracted_file = None

        sizes_to_try = [size] if size else KEY_SIZES

        for test_size in sizes_to_try:
            filename = f"{base_name}_{test_size}_bytes.pem"
            filepath = os.path.join(output_dir, filename)

            print(f"[o] Extracting key with size: {test_size} bytes to {filename}")

            # Seek to address and write to file
            try:
                r2.cmd(f's {address}')
                # Write output to file - using wtf (write to file)
                r2.cmd(f'wtf {filepath} {test_size}')

                # Validate the extracted key
                if validate_key_with_openssl(filepath):
                    print(f"[+] Successfully extracted and validated: {filepath}")
                    extracted_file = filepath
                    break
                else:
                    # Clean up invalid file
                    if os.path.exists(filepath):
                    #    print(f"[o] Keeping invalid key file for debug: {filepath}")
                        os.remove(filepath)
                        #print(f"[o] Removed invalid key file: {filepath}")
            except Exception as e:
                print(f"[!] Error during extraction: {e}")
                continue

        if extracted_file:
            print(f"[✓] Extraction complete for address {address}")

    # Summary
    output_files = [f for f in os.listdir(output_dir) if f.endswith('.pem')]
    print(f"\n[=] Extraction Summary:")
    print(f"[=] Output Directory: {output_dir}")
    print(f"[=] Total Valid Keys Extracted: {len(output_files)}")
    for f in output_files:
        size = os.path.getsize(os.path.join(output_dir, f))
        print(f"   - {f} ({size} bytes)")

    r2.quit()


def main():
    """
    Script entry point
    """
    if len(sys.argv) < 2:
        print("Usage: python3 extract_private_keys.py <path_to_so_file> [output_directory]")
        print("\nExample:")
        print("  python3 extract_private_keys.py ./libcrypto.so.3")
        print("  python3 extract_private_keys.py ./libssl.so.1.1 extracted_keys")
        sys.exit(1)

    binary_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else ".extracted_keys"

    if not os.path.exists(binary_path):
        print(f"[!] Error: Binary file not found at {binary_path}")
        sys.exit(1)

    extract_private_keys(binary_path, output_dir)


if __name__ == "__main__":
    main()
