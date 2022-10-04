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
Description: This script decrypts the strings from 2020 Tokyo Olympics Wiper samples
"""

import os.path

from pefile import PE
import argparse
import sys


def is_invalid_string(string: bytes) -> bool:
    """
    This function checks if the string is invalid, by counting the number of non-valid chars
    :param string: string to verify
    :return: bool
    """
    v = 0
    for c in string:
        if c < 37 or c > 127:
            v += 1
    if v > 4:
        return True
    return False


def decrypt_strings(file_path: str) -> list:
    """
    Decrypts the strings from 2020 Tokyo Olympics Wiper malware
    :param file_path: path of the unpacked sample
    :return: list of strings
    """
    dec, enc = [], []
    try:
        pe = PE(file_path)
    except Exception as e:
        print("[-] Are you sure this file is a PE? (maybe is corrupted)")
        print(f"[-] Error: {repr(e)}")
        return dec

    # The .rdata section is this malware is the second section in the binary
    rdata = pe.sections[1].get_data()

    # Just split the null bytes to get everything
    all_str = list(set(rdata.split(b"\x00")))

    # Searches for invalid strings, ignoring the ones with less than 3 characters
    for i in all_str:
        if len(i) < 3:
            continue
        if is_invalid_string(i):
            enc.append(i)

    # Decrypt all the invalid strings we found
    for s in enc:
        dec.append("".join([chr(~a & 0xff) for a in s]))
    return sorted(dec)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script decrypts strings from unpacked Olympics Wiper samples')
    parser.add_argument('--payload', required=True, action="store", type=str, help='Unpacked Olympics Wiper payload')
    args = parser.parse_args()

    if not args.payload or not os.path.isfile(args.payload):
        print("[-] Please, provide a valid file")
        sys.exit(0)

    dec_strings = decrypt_strings(args.payload)
    if not dec_strings:
        print("[-] Seems that we were unable to decrypt the strings from this sample")
        sys.exit(0)

    print("\n[+] Decrypted strings:\n")
    for item in dec_strings:
        print(item)
