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
Description: This script can be used to unpack Emotet 64-bit samples
"""
import argparse
import struct
import sys


def rolling_xor(binary: bytes, key: str, append_null: bool = True) -> bytes:
    """
    Simple rolling XOR algorithm
    :param binary: binary to be encrypted / decrypted
    :param key: Encryption / decryption key
    :param append_null: Appends a null byte at the end of the string
    :return: bytes
    """
    key = key.encode() if not append_null else f"{key}\x00".encode()
    dec = b""
    for i, b in enumerate(binary):
        dec += struct.pack("B", (b ^ key[i % len(key)]))
    return dec


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script decrypts binaries using a rolling XOR algorithm.')
    parser.add_argument('--payload', required=True, action="store", type=str, help='Binary to decrypt/encrypt')
    parser.add_argument('--key', required=True, action="store", type=str, help='Decryption/encryption key')
    parser.add_argument('--out', required=True, action="store", type=str, help='Output path')
    args = parser.parse_args()

    if not args.payload or not args.key:
        print("[-] Please, provide the required parameters.")
        sys.exit(0)

    with open(args.payload, "rb") as f:
        fb = f.read()

    new_binary = rolling_xor(fb, args.key)
    if not new_binary:
        print("[-] Nothing was decrypted or encrypted")
        sys.exit(0)

    print(f"[+] Saving to {args.out}")
    with open(args.out, "wb") as f:
        f.write(new_binary)

    print("[+] Done")
