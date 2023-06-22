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
Description: This script decrypts strings and the configuration from unpacked BlackMatter ransomware samples

Note: This script was based on the following samples:

    - 22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6
    - 2c323453e959257c7aa86dc180bb3aaaa5c5ec06fa4e72b632d9e4b817052009
    - 7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984
    - c6e2ef30a86baa670590bd21acf5b91822117e0cbe6060060bc5fe0182dace99
"""
import argparse
import binascii
import os
import re
import struct
import sys
from base64 import b64decode
from binascii import hexlify, unhexlify

from capstone import *
from pefile import PE

from aplib import decompress

DEC_STUB = b"8D[A-F0-9]{4,10}(C700.+?)8130([A-F0-9]{8})"


def decrypt_configuration(file_path: str) -> bytes:
    """
    Decrypts the configuration of BlackMatter ransomware
    :param file_path: BlackMatter's binary path
    :return: Decrypted config in bytes
    """
    pe = PE(file_path)

    # The data is located in the fake resource section within the PE file
    rsrc = b""
    for section in pe.sections:
        if b".rsrc" in section.Name:
            rsrc = section.get_data()
            break

    # First 4 bytes are used as a seed to generate the decryption key
    seed = struct.unpack(">I", rsrc[:4][::-1])[0]

    # The next 4 bytes are the length of the encrypted data
    length = int(hexlify(rsrc[4:8][::-1]).decode(), 16)

    # The rest of the bytes are the encrypted data
    enc_data = rsrc[8:8 + length]

    # Constant used to generate the decryption keys (this may change from binary to binary)
    const = 0x8088405

    # The first intermediary value used to generate the key is the seed
    mv = seed

    dec_data = b""
    for i in range(0, len(enc_data), 4):

        # Generate the decryption key
        mv = ((mv * const) & 0xffffffff) + 1
        key = (seed * mv) >> 32

        # Decrypts the data
        for ii, b in enumerate(enc_data[i:i + 4]):
            dec_data += struct.pack(">B", ((key & 0xff) ^ b))
            key = key >> 8

    # Returns the decrypted + decompressed configuration
    return decompress(dec_data)


def decode_config_data(decrypted_configuration: bytes) -> list:
    """
    Decodes the base64 data found in the decrypted configuration
    :param decrypted_configuration: Decrypted BlackMatter configuration
    :return: List with decoded values
    """
    decoded = []
    for item in list(set(decrypted_configuration.split(b"\x00"))):
        if not item:
            continue

        try:
            b64 = b64decode(item)
        except binascii.Error:
            continue

        try:
            dec = [i.replace("\x00", "") for i in b64.decode().split("\x00\x00")]
            if not dec or len(dec) < 2:
                continue
            decoded.append(list(set(dec)))
        except UnicodeDecodeError:
            continue
    return decoded


def decrypt_strings(file_path: str) -> list:
    """
    Decrypts BlackMatter ransomware strings
    :param file_path: Path of the file
    :return: list with decrypted strings
    """
    strings = []
    with open(file_path, "rb") as f:
        fb = f.read()

    # First, we search for possible parts of the code where the decryption stub is located
    for block, key in re.findall(DEC_STUB, hexlify(fb), re.IGNORECASE):
        dec_str, key = "", struct.unpack("<I", unhexlify(key))[0]
        md = Cs(CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        try:
            # If found, we use capstone to disassembly the code, so we can get the operand
            for i in md.disasm(unhexlify(block), len(block)):
                # Skips the counter code
                if "ecx" not in i.op_str:
                    # Decrypts the operand using the key found with regex
                    dec_str += struct.pack("<I", i.operands[1].value.imm ^ key).decode().replace("\x00", "")
            strings.append(dec_str)
        except UnicodeDecodeError:
            continue
    return sorted(list(set(strings)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script decrypts strings and the configuration from BlackMatter')
    parser.add_argument('--payload', required=True, action="store", type=str, help='Unpacked (x86) BlackMatter payload')
    args = parser.parse_args()

    if not args.payload:
        print("[-] Please, provide a BlackMatter unpacked payload")
        sys.exit(0)

    # Paths of where the extracted data will be saved
    bs = os.path.dirname(args.payload)
    dc_p = os.path.join(bs, "decrypted_config.bin")
    ds_p = os.path.join(bs, "decrypted_strings.txt")
    dd_p = os.path.join(bs, "decoded_strings.txt")

    # Decrypts the strings
    ds = decrypt_strings(args.payload)
    if ds:
        print("\n[+] Decrypted strings:\n")
        with open(ds_p, "w") as f:
            for item in ds:
                print(item)
                f.write(f"{item}\n")

    # Decrypts the configuration
    dc = decrypt_configuration(args.payload)
    if dc:
        with open(dc_p, "wb") as f:
            f.write(dc)

    # Decodes base64 values within the configuration
    dd = decode_config_data(dc)
    if dd:
        with open(dd_p, "w") as f:
            for block in dd:
                print("\n[+] Decoded values from decrypted config:")
                for item in block:
                    print(item) if item else None
                    f.write(f"{item}\n")

    if ds_p or dc_p:
        print("\n\n###########\n")
        print(f"[+] ===== Decrypted strings saved at: {ds_p}") if os.path.isfile(ds_p) else None
        print(f"[+] ===== Decrypted configuration saved at: {dc_p}") if os.path.isfile(dc_p) else None
        print(f"[+] ===== Decoded strings saved at: {dd_p}") if os.path.isfile(dd_p) else None
        print("\n########### Goodbye")
