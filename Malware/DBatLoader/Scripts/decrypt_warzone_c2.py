#!/usr/bin/env python3
"""
Copyright 2021 Netskope, Inc.
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
Description: This script decrypts the C2 address from unpacked Warzone RAT samples
"""
import argparse
import struct
import sys

from arc4 import ARC4
from pefile import PE


def get_bss_data(payload: str) -> bytes:
    """
    Gets the data located in the PE .bss section
    :param payload: Warzone PE file path
    :return: Bytes located at the PE .bss section.
    """
    pe = PE(payload)
    for i in pe.sections:
        if b".bss" in i.Name:
            return i.get_data()
    return b""


def decrypt_and_extract_c2(bss_data: bytes) -> str:
    """
    Retrieves the C2 server from Warzone encrypted configuration
    :param bss_data: Data located in Warzone PE .bss section
    :return: C2 address (IP:PORT)
    """
    # Decryption key length
    key_len = struct.unpack("<I", bss_data[:4])[0]

    # Retrieves the decryption key
    dec_key = bss_data[4:4 + key_len]

    # Encrypted configuration
    enc_cfg = bss_data[4 + key_len:]

    # Decrypts the configuration using RC4
    dec_cfg = ARC4(dec_key).decrypt(enc_cfg)

    # C2 length is stored in the first 4 bytes
    c2_len = struct.unpack("<I", dec_cfg[:4])[0]

    # Parses the C2 address
    c2_addr = dec_cfg[4:4 + c2_len].replace(b"\x00", b"").decode()

    # Parses the C2 port
    c2_port = struct.unpack("<H", dec_cfg[c2_len + 4:c2_len + 6])[0]

    # Returns the address in string format (IP:PORT)
    return f"{c2_addr}:{c2_port}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script decrypts and extracts the C2 address from Warzone')
    parser.add_argument('--payload', required=True, action="store", type=str, help='Unpacked Warzone payload')
    args = parser.parse_args()

    if not args.payload:
        print("[-] Please, provide an unpacked Warzone (a.k.a. Ave Maria) payload")
        sys.exit(0)

    pe_bss_data = get_bss_data(args.payload)
    if not pe_bss_data:
        print("[-] Please, make sure this is the unpacked payload of Warzone (a.k.a. Ave Maria")
        sys.exit(0)

    print("[+] Decrypted C2 Address:")
    print(decrypt_and_extract_c2(pe_bss_data))
