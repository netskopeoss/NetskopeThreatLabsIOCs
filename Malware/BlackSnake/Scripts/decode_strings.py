#!/usr/bin/env python3
"""
Copyright 2023 Netskope, Inc.
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
Description: This script can be used to decode BlackSnake ransomware strings.
"""
import argparse
import os
import re
import sys

PATTERN_1 = r"obj\[0\] ?= ?.+?new string"
PATTERN_2 = r"\(([0-9].+?)\^ ([0-9].+?)\)"


def decode_from_file(file_path: str) -> list:
    """
    This function can be used to decode BlackSnake ransomware strings
    :param file_path: BlackSnake code obtained from a .NET decompiler software, like dnSpy
    :return: list of decoded strings
    """
    # List to return
    decoded_strings = []

    # Reads the file
    with open(file_path, "r") as f:
        fs = f.read()

    # Searches for the stack strings and decodes them
    for block in re.findall(PATTERN_1, fs, flags=re.DOTALL):
        decoded_strings.append("".join([chr(int(i[0]) ^ int(i[1])) for i in re.findall(PATTERN_2, block)]))

    return decoded_strings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script can be used to decode BlackSnake ransomware strings ')
    parser.add_argument('--source', required=False, action="store", type=str, help='Path of the decompiled code')
    parser.add_argument('--print', required=False, action="store_true", help='Show strings in the console')
    args = parser.parse_args()

    if not args.source:
        print("[-] Please, provide the ransomware decompiled source code")
        sys.exit(0)

    if not os.path.isfile(args.source):
        print("[-] Please, provide a valid file")
        sys.exit(0)

    strings = decode_from_file(args.source)
    output_file = f"{args.source}_decoded.txt"

    with open(output_file, "w") as of:
        for s in strings:
            of.write(f"{s}\n")

    print(f"\n[+] Decoded strings saved at: {output_file}")

    if args.print:
        print("\n[+] Decoded strings:\n")
        for s in strings:
            print(s)
    print("\n")
