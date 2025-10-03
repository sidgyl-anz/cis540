#!/usr/bin/env python3
"""Brute force Alice's raw-RSA encrypted grade using openssl pkeyutl only."""

import argparse
import os
import subprocess
import tempfile

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


def build_candidates():
    """Generate a small list of plausible plaintext grades."""
    cands = []
    # Whole number scores 0-150, plus newline variants.
    for i in range(0, 151):
        s = str(i).encode()
        cands.append(s)
        cands.append(s + b"\n")
        cands.append(s + b"\r\n")
    # Common grade strings.
    grade_strings = [
        "A+",
        "A",
        "A-",
        "B+",
        "B",
        "B-",
        "C+",
        "C",
        "C-",
        "D+",
        "D",
        "D-",
        "E",
        "F",
        "XF",
        "I",
        "W",
        "P",
        "S",
        "U",
        "AU",
        "NG",
        "Pass",
        "Fail",
    ]
    for g in grade_strings:
        cands.append(g.encode())
    # Deduplicate while preserving order.
    seen = set()
    uniq = []
    for item in cands:
        if item in seen:
            continue
        seen.add(item)
        uniq.append(item)
    return uniq


def write_temp_key():
    """Write the hardcoded public key to a temporary file and return its path."""
    tmp = tempfile.NamedTemporaryFile("w", delete=False)
    try:
        tmp.write(PUBLIC_KEY_PEM)
        return tmp.name
    finally:
        tmp.close()


def openssl_encrypt(pubkey_path, message, modulus_len, mode):
    """Encrypt `message` using openssl pkeyutl.

    The "raw" mode mirrors the previous behaviour of using
    ``-pkeyopt rsa_padding_mode:none`` and left-padding the message to the
    modulus size.  The "default" mode issues the command without any padding
    options, matching the plain ``openssl pkeyutl -encrypt`` invocation shown in
    the lecture screenshot.
    """
    if mode == "raw":
        if len(message) > modulus_len:
            return None
        data = message.rjust(modulus_len, b"\x00")
        extra_args = ["-pkeyopt", "rsa_padding_mode:none"]
    else:
        data = message
        extra_args = []
    tmp_in = tempfile.NamedTemporaryFile(delete=False)
    tmp_out = tempfile.NamedTemporaryFile(delete=False)
    try:
        tmp_in.write(data)
        tmp_in.close()
        tmp_out.close()
        cmd = [
            "openssl",
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            pubkey_path,
        ]
        cmd.extend(extra_args)
        cmd.extend(["-in", tmp_in.name, "-out", tmp_out.name])
        try:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            return None
        with open(tmp_out.name, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(tmp_in.name):
            os.remove(tmp_in.name)
        if os.path.exists(tmp_out.name):
            os.remove(tmp_out.name)


def demo_repeated_encryption(pubkey_path, modulus_len, mode, label):
    """Show whether repeated encryption returns identical ciphertexts."""

    samples = [
        ("ASCII digits '90'", b"90"),
        ("single-byte value 90", bytes([90])),
    ]

    for description, sample_message in samples:
        first = openssl_encrypt(pubkey_path, sample_message, modulus_len, mode)
        second = openssl_encrypt(pubkey_path, sample_message, modulus_len, mode)
        if first is None or second is None:
            print(
                f"[{label}] Unable to encrypt {description} in {mode} mode. "
                "(Sample message may be incompatible.)"
            )
            continue
        same = first == second
        print(
            f"[{label}] Demo encrypting {description} twice in {mode} mode"
        )
        print(f"[{label}] First ciphertext:  {first.hex()}")
        print(f"[{label}] Second ciphertext: {second.hex()}")
        if same:
            print(f"[{label}] Result: ciphertexts MATCH (deterministic)")
        else:
            print(f"[{label}] Result: ciphertexts DIFFER (randomized padding)")
        print()


def parse_args():
    parser = argparse.ArgumentParser(description="Deterministic RSA brute-force helper")
    parser.add_argument(
        "--mode",
        choices=["raw", "default"],
        default="raw",
        help=(
            "Encryption mode: 'raw' uses rsa_padding_mode:none (default), "
            "'default' issues the command with no extra padding options."
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()
    target = bytes.fromhex(TARGET_CIPHER_HEX)
    modulus_len = len(target)
    pubkey_path = write_temp_key()
    try:
        demo_repeated_encryption(pubkey_path, modulus_len, args.mode, "start")
        candidates = build_candidates()
        for idx, cand in enumerate(candidates, start=1):
            cipher = openssl_encrypt(pubkey_path, cand, modulus_len, args.mode)
            if cipher == target:
                print("MATCH FOUND!")
                print("candidate bytes repr:", repr(cand))
                try:
                    print("candidate text:", cand.decode())
                except UnicodeDecodeError:
                    print("candidate text: (non-utf8)")
                demo_repeated_encryption(pubkey_path, modulus_len, args.mode, "end")
                return
            if idx % 100 == 0:
                print(f"Tried {idx} candidates...")
        print("No match found. Try expanding the candidate list.")
        demo_repeated_encryption(pubkey_path, modulus_len, args.mode, "end")
    finally:
        if os.path.exists(pubkey_path):
            os.remove(pubkey_path)


if __name__ == "__main__":
    main()
