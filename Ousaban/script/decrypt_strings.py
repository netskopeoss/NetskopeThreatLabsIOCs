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
Description: This script can be used to decrypt strings found in Brazilian-based banking malware (e.g. Ousaban,
Guildma, Grandoreiro, etc)
"""


import argparse
import json
import os
import sys
from binascii import unhexlify


def decrypt_string(encrypted_string: str, decryption_key: bytes) -> str:
    """
    Decrypts strings commonly found in Brazilian sourced banking malware
    :param encrypted_string: Encrypted string
    :param decryption_key: Decryption key
    :return: str
    """
    decrypted_string = ""
    encrypted_string = unhexlify(encrypted_string)
    aux = encrypted_string[0]
    for i, eb in enumerate(encrypted_string[1:]):
        db = eb ^ decryption_key[i % len(decryption_key)]
        decrypted_string += chr(db + 0xff - aux) if db < aux else chr(db - aux)
        aux = eb
    return decrypted_string


def decrypt_from_file(file_path: str, decryption_key: bytes) -> dict:
    """
    Decrypts strings commonly found in Brazilian sourced banking malware from a file
    :param file_path: File containing encrypted strings
    :param decryption_key: Decryption key
    :return: dict
    """
    data = {}
    with open(file_path, 'r') as f:
        encrypted_strings = f.read().split('\n')

    for s in encrypted_strings:
        try:
            data[s] = decrypt_string(s, decryption_key)
        except Exception as e:
            print(f"[-] Cannot decrypt {s}: {repr(e)}")

    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script decrypts strings from banking trojans common in LATAM')
    parser.add_argument('--key', required=True, action="store", type=str, help='Decryption key')
    parser.add_argument('--string', required=False, action="store", type=str, help='Path with encrypted strings')
    parser.add_argument('--strings', required=False, action="store", type=str, help='Path with encrypted strings')
    parser.add_argument('--print', required=False, action="store_true", help='Show strings in the console')
    args = parser.parse_args()

    if not args.key or (not args.string and not args.strings):
        print("[-] Please, provide the key and a single string or a list of strings to decrypt")
        sys.exit(0)

    if args.string:
        print(f"\n[+] Decrypting {args.string}\n")
        print(f"{decrypt_string(args.string, args.key.encode())}\n")
        sys.exit(0)

    if not os.path.isfile(args.strings):
        print("[-] Strings must be provided within a file")
        sys.exit(0)

    strings = decrypt_from_file(args.strings, args.key.encode())
    output_file = f"{args.strings}_decrypted.json"

    with open(output_file, "w") as of:
        of.write(json.dumps(strings))

    print(f"\n[+] Decrypted strings saved at: {output_file}")

    if args.print:
        print("\n[+] Decrypted strings:\n")
        for string in strings:
            print(strings[string])

    print("\n")
