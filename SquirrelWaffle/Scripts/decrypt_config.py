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
Description: This script decrypts the configuration from unpacked SquirrelWaffle DLL samples.
"""
import argparse
import sys

from pefile import PE


def decrypt(data: bytes, key: bytes) -> bytes:
    """
    Simple XOR decrypt for SquirrelWaffle
    :param data: Encrypted data
    :param key: Decryption Key
    :return: Decrypted data
    """
    dec = b''
    for i, b in enumerate(data):
        dec += chr(b ^ key[i % len(key)]).encode()
    return dec


def get_rdata(file_path: str) -> bytes:
    """
    Reads a PE file and returns the data from the ".rdata" section
    :param file_path: PE file path
    :return: ".rdata" bytes
    """
    pe = PE(file_path)
    for i in pe.sections:
        if b"rdata" in i.Name:
            return i.get_data()
    return b''


def beautify(decrypted_data: bytes) -> list:
    """
    Just to organize the decrypted data
    :param decrypted_data: SquirrelWaffle decrypted data
    :return: list with unique values
    """
    items = decrypted_data.split(b"\r\n") if b"\r\n" in decrypted_data else decrypted_data.split(b"|")
    return sorted(list(set([i for i in items if i != b''])))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script decrypts data from unpacked SquirrelWaffle samples')
    parser.add_argument('--payload', required=True, action="store", type=str, help='Unpacked SquirrelWaffle payload')
    args = parser.parse_args()

    if not args.payload:
        print("[-] Please, provide a SquirrelWaffle unpacked payload")
        sys.exit(0)

    # Reads the PE .rdata section, which is where the encrypted information is stored
    rdata = get_rdata(args.payload)

    # Builds a list of strings based on the null bytes
    strings = [i for i in rdata.split(b"\x00") if i != b'']

    # Enumerates all the strings
    for i, ii in enumerate(strings, start=0):

        # Only tries to decrypt the largest blocks (IPs \ C2 list)
        if len(ii) > 200:

            # Tries to decrypt the string
            dec_str = decrypt(strings[i], strings[i + 1])

            # Prints all the values in the screen
            print("\n[+] Decrypted data:\n")
            for item in beautify(dec_str):
                print(f"{item.decode()}")
