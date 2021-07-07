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
Description: This script decrypts the configuration from unpacked REvil samples
"""

import os
import sys
import struct
import pefile
import argparse

from arc4 import ARC4


def decrypt_config(file_path: str):
    """
    Decrypts the configuration from REvil
    :param file_path: Unpacked payload
    :return: JSON config
    """
    if not os.path.isfile(file_path):
        print("[-] Invalid file path")
        return None

    # Loads the PE file
    pe = pefile.PE(file_path)

    # Checks the amount of sections. Usually, a unpacked REvil samples has more than 4 sections
    if len(pe.sections) < 4:
        return None

    # The encrypted data is within the fourth section of the binary
    section_data = pe.sections[3].get_data()

    # The 4 bytes at 0x24 indicates the length of the encrypted data
    data_length = struct.unpack('I', section_data[0x24:0x28])[0]

    # The decryption key is the first 32 bytes of the section
    dec_key = section_data[:0x20]

    # Finally, decrypts the bytes using RC4
    dec_data = ARC4(dec_key).decrypt(section_data[0x28:0x28 + data_length])
    return dec_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script decrypts the configuration from unpacked REvil samples')
    parser.add_argument('--payload', required=True, action="store", type=str, help='Unpacked REvil payload')
    args = parser.parse_args()

    if not args.payload:
        print("[-] Please, provide a REvil unpacked payload")
        sys.exit(0)

    dec_config = decrypt_config(args.payload)
    if not dec_config:
        print("[-] Please, make sure this is the unpacked payload of REvil")
        sys.exit(0)

    dec_path = os.path.join(os.path.dirname(args.payload), 'decrypted.json')
    with open(dec_path, 'wb') as f:
        f.write(dec_config)
    print(f"[+] Decrypted configuration saved at: {dec_path}")

