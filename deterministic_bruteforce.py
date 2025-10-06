#!/usr/bin/env python3
"""Recover Alice's RSA-encrypted grade by testing small integers.

This script demonstrates two equivalent approaches for encrypting a raw RSA
plaintext:

* ``openssl pkeyutl`` with ``rsa_padding_mode:none``
* a direct modular exponentiation performed in Python

Both methods are executed for every integer in the configured search window to
verify that they produce identical ciphertexts.  When a ciphertext matches the
provided target value the corresponding grade is reported.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Iterable

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKClTqiJTUa++IPogThEsiNR4J
FpmV12jbfYvEc74ZtyCxGYpt3UcwaYbBoVgBpFepBRnwjJEPX8jxip7yfxr/vqYv
MrQ4LJggKRKUDrWFwuI+lNmxsVz+E4now0v1E/lHa5p8PxdqRBdm1xw4yXx48Xft
rnnCa8w19lq20OSNPwIDAQAB
-----END PUBLIC KEY-----
"""

TARGET_CIPHER_HEX = (
    "9A60E4CE8D70B2A12BB2422D73571A445159955A844AE5EA9995870AA4819BA4"
    "34835C88AB4F1FBD17712DC525613382FF6A9621CB9BC0F82191EB60AAA369FC"
    "061A614C18F81FA9906FB168E0E8B0A0EA5C3A9E6E1566820E4831CAA9BDF0FB"
    "048F8095DE65DB6D9FA79AFF7D40529E512ADB91231D176944064200AEC070A1"
)


@dataclass(frozen=True)
class PublicKeyInfo:
    modulus: int
    exponent: int
    modulus_bytes: int


@dataclass(frozen=True)
class EncryptionAttempt:
    grade: int
    openssl_cipher: bytes
    python_cipher: bytes

    @property
    def matches_target(self) -> bool:
        return self.openssl_cipher == TARGET_CIPHER_BYTES

    def validate(self) -> None:
        if self.openssl_cipher != self.python_cipher:
            raise RuntimeError(
                "OpenSSL and Python modular exponentiation produced different"
                " ciphertexts for grade {}".format(self.grade)
            )


TARGET_CIPHER_BYTES = bytes.fromhex(TARGET_CIPHER_HEX)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Search for Alice's grade by encrypting integers with OpenSSL and"
            " Python's modular exponentiation"
        )
    )
    parser.add_argument(
        "--max-grade",
        type=int,
        default=300,
        help=(
            "Highest grade (inclusive) to test.  Both encryption methods are"
            " run for every integer in the range 0..max-grade."
        ),
    )
    return parser.parse_args()


def load_public_key(pubkey_path: str) -> PublicKeyInfo:
    result = subprocess.run(
        ["openssl", "rsa", "-pubin", "-in", pubkey_path, "-text", "-noout"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    modulus_lines = []
    exponent_line = None
    reading_modulus = False
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Modulus:"):
            reading_modulus = True
            continue
        if stripped.startswith("Exponent:"):
            exponent_line = stripped
            break
        if reading_modulus and stripped:
            modulus_lines.append(stripped)
    if not modulus_lines or exponent_line is None:
        raise RuntimeError("Failed to parse modulus/exponent from openssl output")
    modulus_hex = "".join(segment.replace(":", "") for segment in modulus_lines)
    modulus = int(modulus_hex, 16)
    exponent = int(exponent_line.split()[1])
    modulus_bytes = (modulus.bit_length() + 7) // 8
    return PublicKeyInfo(modulus, exponent, modulus_bytes)


def write_temp_key() -> str:
    tmp = tempfile.NamedTemporaryFile("w", delete=False)
    try:
        tmp.write(PUBLIC_KEY_PEM)
        return tmp.name
    finally:
        tmp.close()


def run_openssl_raw_encrypt(pubkey_path: str, plaintext: bytes) -> bytes:
    tmp_in = tempfile.NamedTemporaryFile(delete=False)
    tmp_out = tempfile.NamedTemporaryFile(delete=False)
    try:
        tmp_in.write(plaintext)
        tmp_in.close()
        tmp_out.close()
        cmd = [
            "openssl",
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            pubkey_path,
            "-in",
            tmp_in.name,
            "-out",
            tmp_out.name,
            "-pkeyopt",
            "rsa_padding_mode:none",
        ]
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise RuntimeError("openssl pkeyutl failed for plaintext {}".format(plaintext))
        with open(tmp_out.name, "rb") as f:
            return f.read()
    finally:
        for path in (tmp_in.name, tmp_out.name):
            if os.path.exists(path):
                os.remove(path)


def python_raw_encrypt(grade: int, key: PublicKeyInfo) -> bytes:
    cipher_int = pow(grade, key.exponent, key.modulus)
    return cipher_int.to_bytes(key.modulus_bytes, "big")


def search_grades(grades: Iterable[int], key: PublicKeyInfo, pubkey_path: str) -> EncryptionAttempt | None:
    for grade in grades:
        padded_plaintext = grade.to_bytes(key.modulus_bytes, "big")
        openssl_cipher = run_openssl_raw_encrypt(pubkey_path, padded_plaintext)
        python_cipher = python_raw_encrypt(grade, key)
        attempt = EncryptionAttempt(grade, openssl_cipher, python_cipher)
        attempt.validate()
        if attempt.matches_target and int.from_bytes(padded_plaintext, "big") == grade:
            return attempt
    return None


def main() -> None:
    args = parse_args()
    pubkey_path = write_temp_key()
    try:
        key = load_public_key(pubkey_path)
        print("Target ciphertext (hex):")
        print(TARGET_CIPHER_HEX)
        search_range = range(0, args.max_grade + 1)
        attempt = search_grades(search_range, key, pubkey_path)
        if attempt is None:
            print(
                "No grade in the range 0-{} produced the target ciphertext.".format(
                    args.max_grade
                )
            )
            return
        print("Match found!")
        print("grade:", attempt.grade)
        print("ciphertext (hex):", attempt.openssl_cipher.hex())
        print("plaintext bytes (hex):", attempt.grade.to_bytes(key.modulus_bytes, "big").hex())
    finally:
        if os.path.exists(pubkey_path):
            os.remove(pubkey_path)


if __name__ == "__main__":
    main()
