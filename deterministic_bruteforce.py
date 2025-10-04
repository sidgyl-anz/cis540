#!/usr/bin/env python3
"""Brute force Alice's RSA-encrypted grade using openssl pkeyutl only."""

import csv
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


WORDS_0_TO_19 = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
]

TENS_WORDS = [
    "",
    "",
    "twenty",
    "thirty",
    "forty",
    "fifty",
    "sixty",
    "seventy",
    "eighty",
    "ninety",
]


def _two_digit_words(n):
    """Return the English words for ``n`` where ``0 <= n < 100``."""

    if not 0 <= n < 100:
        raise ValueError("Expected a number between 0 and 99 inclusive")
    if n < 20:
        return WORDS_0_TO_19[n]
    tens, ones = divmod(n, 10)
    if ones == 0:
        return TENS_WORDS[tens]
    return f"{TENS_WORDS[tens]}-{WORDS_0_TO_19[ones]}"


def number_to_words(n):
    """Convert ``n`` (0-150) to its English words representation."""

    if not 0 <= n <= 150:
        raise ValueError("Only numbers from 0 through 150 are supported")
    if n < 100:
        return _two_digit_words(n)
    if n == 100:
        return "one hundred"
    remainder = n - 100
    remainder_words = _two_digit_words(remainder)
    return f"one hundred {remainder_words}"


def build_candidates():
    """Generate a small list of plausible plaintext grades."""
    cands = []
    # Whole number scores 0-150 as ASCII bytes, plus newline variants.
    for i in range(0, 151):
        s = str(i).encode("ascii")
        cands.append(s)
        cands.append(s + b"\n")
        cands.append(s + b"\r\n")
        # Single-byte value for the numeric grade, plus newline variants.
        raw_byte = bytes([i])
        cands.append(raw_byte)
        cands.append(raw_byte + b"\n")
        cands.append(raw_byte + b"\r\n")
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


def verify_mode_reproducibility(pubkey_path, modulus_len, padding_modes):
    """Encrypt a sample grade multiple times and show the ciphertexts.

    Returns a ``dict`` mapping each padding mode to ``True`` when reproducible.
    """

    test_plaintext = b"100"
    samples_per_mode = 3
    print(
        "Verifying reproducibility of encrypting b'100' under each padding mode by"
        f" running {samples_per_mode} sample encryptions..."
    )
    reproducible = {}
    for padding_mode in padding_modes:
        sample_ciphertexts = []
        for attempt in range(1, samples_per_mode + 1):
            cipher = openssl_encrypt(
                pubkey_path, test_plaintext, modulus_len, padding_mode
            )
            if cipher is None:
                print(
                    f"  {padding_mode}: plaintext too long for this padding mode; skipping"
                    " sample display"
                )
                reproducible[padding_mode] = False
                break
            sample_ciphertexts.append(cipher)
            print(f"  {padding_mode} sample #{attempt}: {cipher.hex()}")
        else:
            unique_ciphertexts = {c for c in sample_ciphertexts}
            if len(unique_ciphertexts) == 1:
                print(
                    f"  {padding_mode}: ciphertexts identical across {samples_per_mode} attempts"
                )
                reproducible[padding_mode] = True
            else:
                print(
                    f"  {padding_mode}: ciphertexts differ across {samples_per_mode} attempts"
                )
                reproducible[padding_mode] = False
    return reproducible


def main():
    target = bytes.fromhex(TARGET_CIPHER_HEX)
    modulus_len = len(target)
    pubkey_path = write_temp_key()
    padding_modes = ("none", "pkcs1", "default")
    print("Target ciphertext (hex):")
    print(TARGET_CIPHER_HEX)
    log_path = os.path.join(os.getcwd(), "bruteforce_attempts_log.csv")
    example_attempts_to_print = 5
    printed_examples = 0
    notified_log_only = False
    try:
        reproducible = verify_mode_reproducibility(
            pubkey_path, modulus_len, padding_modes
        )
        unusable_modes = [
            mode for mode, is_reproducible in reproducible.items() if not is_reproducible
        ]
        if unusable_modes:
            print(
                "NOTE: The following padding modes appear nondeterministic but will still be\n"
                "      attempted as requested: " + ", ".join(unusable_modes)
            )
        print("Proceeding with all padding modes: none, pkcs1, default")
        candidates = build_candidates()
        attempts = 0
        with open(log_path, "w", newline="", encoding="utf-8") as log_file:
            writer = csv.writer(log_file)
            header = [
                "attempt_number",
                "candidate_index",
                "padding_mode",
                "candidate_repr",
                "cipher_hex",
            ]
            writer.writerow(header)
            print("# Attempt log examples (full log written to bruteforce_attempts_log.csv)")
            print(",".join(header))
            for idx, cand in enumerate(candidates, start=1):
                for padding_mode in padding_modes:
                    cipher = openssl_encrypt(
                        pubkey_path, cand, modulus_len, padding_mode
                    )
                    if cipher is None:
                        continue
                    attempts += 1
                    row = [
                        attempts,
                        idx,
                        padding_mode,
                        repr(cand),
                        cipher.hex(),
                    ]
                    writer.writerow(row)
                    log_file.flush()
                    if printed_examples < example_attempts_to_print:
                        print(",".join(str(value) for value in row))
                        printed_examples += 1
                        if printed_examples == example_attempts_to_print:
                            print(
                                "(Further attempts are logged to bruteforce_attempts_log.csv only.)"
                            )
                    elif not notified_log_only:
                        print(
                            "(All additional attempts are recorded in bruteforce_attempts_log.csv.)"
                        )
                        notified_log_only = True
                    if cipher == target:
                        print("MATCH FOUND!")
                        print("padding mode:", padding_mode)
                        print("candidate bytes repr:", repr(cand))
                        try:
                            candidate_text = cand.decode()
                        except UnicodeDecodeError:
                            print("candidate text: (non-utf8)")
                        else:
                            print("candidate text:", candidate_text)
                        return
                if idx % 100 == 0:
                    print(
                        "Tried "
                        f"{idx} candidates across {len(padding_modes)} padding modes"
                        f" ({attempts} successful encryptions)..."
                    )
        print("No match found. Try expanding the candidate list.")
        print(f"Attempt details logged to {log_path} and echoed above.")
    finally:
        if os.path.exists(pubkey_path):
            os.remove(pubkey_path)


if __name__ == "__main__":
    main()
