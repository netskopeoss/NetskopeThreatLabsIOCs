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
Description: This script can be used to decrypt AsyncRAT strings.
"""
import argparse
import json
import os
import sys
from base64 import b64decode
from hashlib import pbkdf2_hmac

from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms


def get_derived_key(password: bytes, salt: bytes, hash_type: str, iteration_count: int, key_length: int) -> bytes:
    """
    Generates a Key derivation based on a password using PKCS#5
    :param password: Password used to generate the key
    :param salt: Salt used to randomize the hash
    :param hash_type: Hashing type (e.g. SHA1)
    :param iteration_count: Number of iterations
    :param key_length: Key length
    :return: decrypted data
    """
    return pbkdf2_hmac(hash_type, password, salt, iteration_count, dklen=key_length)


def aes_decrypt(to_decrypt: bytes, key: bytes, iv: bytes, mode: int) -> bytes:
    """
    Decrypts data using AES
    :param to_decrypt: Data to decrypt
    :param key: Decryption key
    :param iv: Initialization value
    :param mode: Decryption mode (e.g. AES.MODE_CBC)
    :return: decrypted data
    """
    p = padding.PKCS7(algorithms.AES(key).block_size).unpadder()
    return p.update(AES.new(key, mode, iv=iv).decrypt(to_decrypt)) + p.finalize()


def decrypt_string(encrypted_string: bytes, password: bytes, salt: bytes) -> str:
    """
    Decrypts AsyncRAT strings
    :param encrypted_string: Encrypted string
    :param password: Password used to generate the key
    :param salt: Salt
    :return: str
    """
    key = get_derived_key(b64decode(password), b64decode(salt), hash_type="SHA1", iteration_count=50000, key_length=32)
    decoded_str = b64decode(encrypted_string)
    return aes_decrypt(decoded_str[48:], key, decoded_str[32:48], AES.MODE_CBC).decode()


def decrypt_from_file(file_path: str, password: bytes, salt: bytes) -> dict:
    """
    Decrypts AsyncRAT strings from a file
    :param file_path: File containing encrypted strings
    :param password: Password used to generate the key
    :param salt: Salt
    :return: dict
    """
    data = {}
    with open(file_path, 'r') as f:
        encrypted_strings = f.read().split('\n')

    for s in encrypted_strings:
        try:
            data[s] = decrypt_string(s.encode(), password, salt)
        except Exception as e:
            print(f"[-] Cannot decrypt {s}: {repr(e)}")
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script can be used to decrypt AsyncRAT strings ')
    parser.add_argument('--password', required=True, action="store", type=str, help='Decryption password')
    parser.add_argument('--salt', required=True, action="store", type=str, help='Salt')
    parser.add_argument('--string', required=False, action="store", type=str, help='Single string to decrypt')
    parser.add_argument('--strings', required=False, action="store", type=str, help='Path with encrypted strings')
    parser.add_argument('--print', required=False, action="store_true", help='Show strings in the console')
    args = parser.parse_args()

    if not args.password or not args.salt or (not args.string and not args.strings):
        print("[-] Please, provide the password, salt and a single string or a list of strings to decrypt")
        sys.exit(0)

    if args.string:
        print(f"\n[+] Decrypting {args.string}\n")
        print(f"{decrypt_string(args.string.encode(), args.password.encode(), args.salt.encode())}\n")
        sys.exit(0)

    if not os.path.isfile(args.strings):
        print("[-] Strings must be provided within a file")
        sys.exit(0)

    strings = decrypt_from_file(args.strings, args.password.encode(), args.salt.encode())
    output_file = f"{args.strings}_decrypted.json"

    with open(output_file, "w") as of:
        of.write(json.dumps(strings))

    print(f"\n[+] Decrypted strings saved at: {output_file}")

    if args.print:
        print("\n[+] Decrypted strings:\n")
        for string in strings:
            print(strings[string])

    print("\n")
