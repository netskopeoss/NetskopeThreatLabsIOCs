#!/usr/bin/env python3
"""
Copyright 2022 Netskope, Inc.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Written by Gustavo Palazolo
Description: This script decrypts the C2 address from unpacked Emotet 64-bit samples
"""
import argparse
import os
import struct
import sys

from pefile import PE

# Known ports used by Emotet
KNOWN_PORTS = [4143, 443, 7080, 80, 8080]


def get_c2_addresses(pe: PE) -> list:
    """
    Tries to decrypt Emotet's C2 addresses
    :param pe: PE file
    :return: list of addresses
    """
    addresses, data_section = [], b""

    # The addresses are located in the .data section
    for section in pe.sections:
        if b".data" in section.Name:
            data_section = section.get_data()
            break

    # The first 4 bytes are the decryption key
    key, dec = data_section[:4], b""
    for i, b in enumerate(data_section[8:]):
        dec += struct.pack("B", b ^ (key[i % len(key)]))

    # Parses the addresses
    for i in range(0, len(dec), 8):
        ip, port = f"{dec[i + 0]}.{dec[i + 1]}.{dec[i + 2]}.{dec[i + 3]}", struct.unpack('>H', dec[i + 4:i + 6])[0]
        if port in KNOWN_PORTS:
            addresses.append(f"{ip}:{port}")

    return sorted(list(set(addresses)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script decrypts Emotet\'s C2 addresses.')
    parser.add_argument('--payload', required=True, action="store", type=str, help='Unpacked Emotet sample')
    args = parser.parse_args()

    if not args.payload:
        print("[-] Please, provide the required parameters.")
        sys.exit(0)

    if not os.path.isfile(args.payload):
        print("[-] Not a valid file.")
        sys.exit(0)

    try:
        pe_file = PE(args.payload)
    except Exception as e:
        print(f"[-] Error: {repr(e)}")
        sys.exit(0)

    decrypted_addresses = get_c2_addresses(pe_file)
    print("\n[+] Total of addresses:")
    print(len(decrypted_addresses))

    print("\n[+] C2 Addresses:\n")
    for item in decrypted_addresses:
        print(item)
