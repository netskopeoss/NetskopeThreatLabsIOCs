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
Description: This script can be used to decrypt Ousaban malware payloads.
"""

import argparse
import os
import struct
import sys


def decrypt_file(encrypted_bytes: bytes, key: bytes) -> bytes:
    """
    Decrypts Ousaban payload files
    :param encrypted_bytes: Bytes from the encrypted file
    :param key: Key used by the injector
    :return: Decrypted bytes
    """
    decrypted = b""
    for i, b in enumerate(encrypted_bytes):
        ps = i % len(key)
        db = b ^ i if i & 1 == 0 else b ^ (len(key) - ps)
        decrypted += struct.pack('B', (db ^ key[ps]) & 0xff)
    return decrypted


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script decrypts Ousaban payloads')
    parser.add_argument('--key', required=True, action="store", type=str, help='Decryption key found in the injector')
    parser.add_argument('--payload', required=True, action="store", type=str, help='Encrypted payload path')
    args = parser.parse_args()

    if not args.key or not args.payload:
        print("[-] Please, provide the correct arguments")
        sys.exit(0)

    if not os.path.isfile(args.payload):
        print("[-] File passed as argument doesn't exist")
        sys.exit(0)

    # Reads the encrypted file
    with open(args.payload, "rb") as f:
        fb = f.read()

    # Tries to decrypt
    decrypted_file = decrypt_file(fb, args.key)

    # Saving the decrypted bytes
    dec_path = f"{args.payload}_decrypted.bin"
    with open(dec_path, "wb") as f:
        f.write(decrypted_file)

    print(f"[+] Decrypted payload saved at: {dec_path}")
