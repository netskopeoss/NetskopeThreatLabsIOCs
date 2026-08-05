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
Description: This script extracts malicious URLs found in Emotet spreadsheets, which abuses Excel 4.0 (XLM) Macros
"""

import argparse
import json
import os
import re
import sys

from XLMMacroDeobfuscator.deobfuscator import process_file

PATTERN = r"CALL\(\"urlmon\", ?\"URLDownloadToFileA\".+?(http.+?)\""


def analyze_files(directory: str) -> dict:
    """
    Analyze the files with XLM Deobfuscator tool and searches for URLs using regex.
    :param directory: Path where the excel spreadsheets are located.
    :return: dictionary with the results
    """
    urls = {}
    for f in os.listdir(directory):
        print(f"[+] Processing file {f}")
        fp = os.path.join(directory, f)

        # Creates a list to append all the URLs found in the deobfuscated code
        urls[f] = []

        # Tries to extract and deobfuscate the code
        try:
            xlm = process_file(file=fp, silent=True, noninteractive=True, noindent=True, return_deobfuscated=True)
        except Exception as e:
            print(f"[-] Error processing file {f}: {repr(e)}")
            continue

        # If we have results from the tool, we iterate over the cells to search for URLs
        for cell in xlm:
            for url in re.findall(PATTERN, cell, flags=re.IGNORECASE):
                urls[f].append(url)

    return urls


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script extracts IOCs from Emotet spreadsheet files')
    parser.add_argument('--path', required=True, action="store", type=str, help='Path where the files are located')
    parser.add_argument('--out', required=True, action="store", type=str, help='Output path')
    args = parser.parse_args()

    if not args.path or not args.out:
        print("[-] Please, provide the required parameters.")
        sys.exit(0)

    if not os.path.isdir(args.out):
        os.mkdir(args.out)

    output = analyze_files(args.path)
    output_path = os.path.join(args.out, "results.json")
    with open(output_path, "w") as output_file:
        output_file.write(json.dumps(output))

    print(f"[+] Results saved to: {output_path}")
    print("[+] Done")
