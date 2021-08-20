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
Description: This script generates the hashes used by BlackMatter to decode API calls

Note: This script was based on the following samples (all Windows versions of BlackMatter):

    - 22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6
    - 2c323453e959257c7aa86dc180bb3aaaa5c5ec06fa4e72b632d9e4b817052009
    - 7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984
    - c6e2ef30a86baa670590bd21acf5b91822117e0cbe6060060bc5fe0182dace99
"""
import argparse


def ror(val, rb, mb=32):
    return ((val & (2 ** mb - 1)) >> rb % mb) | (val << (mb - (rb % mb)) & (2 ** mb - 1))


def create_hash(s, h=0x0):
    for i in f"{s}\x00":
        h = ror(h, 13) + ord(i)
    return h


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generates the hashes used by BlackMatter to decode API calls')
    parser.add_argument('--str', required=True, action="store", type=str, help='API call (eg: kernel32.LoadLibrayA)')
    args = parser.parse_args()

    dll_name = f"{args.str.split('.')[0]}.dll"
    api_name = args.str.split('.')[1]

    dll_hash = create_hash(dll_name)
    full_hash = create_hash(api_name, dll_hash)

    key = 0x22065FED

    print(f"\n[+] DLL: {dll_name}")
    print(f"[+] API: {api_name}")
    print(f"\n[+] DLL hash: {hex(dll_hash)}")
    print(f"[+] DLL + API hash: {hex(full_hash)}")
    print(f"[+] Encoded hash (using {hex(key)} as key): {hex(full_hash ^ key)}\n")
