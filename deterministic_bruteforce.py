#!/usr/bin/env python3
"""Brute force Alice's raw-RSA encrypted grade using openssl pkeyutl only."""

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
    for g in ["A", "A+", "A-", "B", "B+", "B-", "C", "D", "F", "Pass", "Fail"]:
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


def openssl_encrypt_raw(pubkey_path, message, modulus_len):
    """Encrypt `message` using openssl pkeyutl with raw RSA padding."""
    if len(message) > modulus_len:
        return None
    padded = message.rjust(modulus_len, b"\x00")
    tmp_in = tempfile.NamedTemporaryFile(delete=False)
    tmp_out = tempfile.NamedTemporaryFile(delete=False)
    try:
        tmp_in.write(padded)
        tmp_in.close()
        tmp_out.close()
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey",
                pubkey_path,
                "-pkeyopt",
                "rsa_padding_mode:none",
                "-in",
                tmp_in.name,
                "-out",
                tmp_out.name,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(tmp_out.name, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(tmp_in.name):
            os.remove(tmp_in.name)
        if os.path.exists(tmp_out.name):
            os.remove(tmp_out.name)


def main():
    target = bytes.fromhex(TARGET_CIPHER_HEX)
    modulus_len = len(target)
    pubkey_path = write_temp_key()
    try:
        candidates = build_candidates()
        for idx, cand in enumerate(candidates, start=1):
            cipher = openssl_encrypt_raw(pubkey_path, cand, modulus_len)
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
