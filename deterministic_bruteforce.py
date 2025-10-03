#!/usr/bin/env python3
"""Brute force Alice's RSA-encrypted grade using openssl pkeyutl only."""

import os
import argparse
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


def openssl_encrypt(pubkey_path, message, modulus_len, padding_mode):
    """Encrypt ``message`` using ``openssl pkeyutl`` with the requested padding.

    ``padding_mode`` may be ``"none"`` for raw RSA (zero-left-padded to the
    modulus length), ``"pkcs1"`` to request explicit PKCS#1 v1.5 padding via
    ``-pkeyopt``, or ``"default"`` to invoke the command with no padding
    options (``openssl``'s default is PKCS#1 padding). When the plaintext is too
    large for the requested padding, ``None`` is returned instead of raising.
    """
    if padding_mode == "none":
        if len(message) > modulus_len:
            return None
        input_bytes = message.rjust(modulus_len, b"\x00")
    else:
        if len(message) >= modulus_len:
            return None
        input_bytes = message
    tmp_in = tempfile.NamedTemporaryFile(delete=False)
    tmp_out = tempfile.NamedTemporaryFile(delete=False)
    try:
        tmp_in.write(input_bytes)
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
        ]
        if padding_mode == "none":
            cmd.extend(["-pkeyopt", "rsa_padding_mode:none"])
        elif padding_mode == "pkcs1":
            cmd.extend(["-pkeyopt", "rsa_padding_mode:pkcs1"])
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(tmp_out.name, "rb") as f:
            return f.read()
    except subprocess.CalledProcessError:
        return None
    finally:
        if os.path.exists(tmp_in.name):
            os.remove(tmp_in.name)
        if os.path.exists(tmp_out.name):
            os.remove(tmp_out.name)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--padding-mode",
        choices=["none", "pkcs1", "default"],
        default="none",
        help=(
            "Padding mode for openssl pkeyutl. Use 'none' for raw RSA (default), "
            "'pkcs1' to explicitly request PKCS#1 padding, or 'default' to run "
            "without any padding options."
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()
    target = bytes.fromhex(TARGET_CIPHER_HEX)
    modulus_len = len(target)
    pubkey_path = write_temp_key()
    try:
        candidates = build_candidates()
        for idx, cand in enumerate(candidates, start=1):
            cipher = openssl_encrypt(pubkey_path, cand, modulus_len, args.padding_mode)
            if cipher == target:
                print("MATCH FOUND!")
                print("candidate bytes repr:", repr(cand))
                try:
                    print("candidate text:", cand.decode())
                except UnicodeDecodeError:
                    print("candidate text: (non-utf8)")
                return
            if idx % 100 == 0:
                print(f"Tried {idx} candidates...")
        print("No match found. Try expanding the candidate list.")
    finally:
        if os.path.exists(pubkey_path):
            os.remove(pubkey_path)


if __name__ == "__main__":
    main()
