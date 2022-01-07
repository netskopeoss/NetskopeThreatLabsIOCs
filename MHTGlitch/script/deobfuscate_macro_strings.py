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
Description: This script decodes strings from malicious VBA code, found in the MHTGlitch campaign.
"""
import argparse
import os
import re
import sys

from numexpr import evaluate

PATTERNS = [r"Chr\(\((.+?)\)\)", r"[\=|\+|\-] \((.+?)\)"]


def decode_strings(vba: str) -> list:
    """
    Decode strings commonly found in malicious VBA code from MHTGlitch samples.
    :param vba: Content from the extracted VBA macro
    :return: List of decoded strings
    """
    # List to be returned
    strings = []

    # Parse the file line by line
    for line in vba.split("\n"):

        # Tries both string patterns we found in the analyzed macros
        for exp in PATTERNS:
            items = re.findall(exp, line)

            # Skip the line if the pattern wasn't found
            if not items:
                continue

            # Replace the octal and hexadecimal representations
            items = [i.replace("&O", "0o").replace("&H", "0x") for i in items]

            # Creates the string
            strings.append("".join([chr(evaluate(i).item()) for i in items]))

    return strings


if __name__ == "__main__":
    description = "This script decodes strings from malicious VBA code, found in the MHTGlitch campaign."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--payload', required=True, action="store", type=str, help='Extracted malicious VBA code')
    args = parser.parse_args()

    if not args.payload or not os.path.isfile(args.payload):
        print("[-] Please, provide the extracted VBA code from the infected document")
        sys.exit(0)

    # Read the VBA content
    with open(args.payload, "r") as f:
        vba_content = f.read()

    # Tries to decode the strings
    decoded_strings = decode_strings(vba_content)
    if not decoded_strings:
        print(f"[+] Couldn't extract the strings from this macro")
        sys.exit(0)

    # Prints everything in the console
    print("[+] Decoded strings: ")
    for string in decoded_strings:
        print(string)
