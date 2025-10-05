#!/usr/bin/env python3
"""Brute force Alice's RSA-encrypted grade using :command:`openssl pkeyutl`.

The script performs three high-level steps:

1. Build a list of plausible plaintext grade candidates.
2. Demonstrate whether repeated encryptions of a sample grade are deterministic
   for three padding modes (``none``, ``pkcs1``, and ``default``).
3. Brute-force the ciphertext under each padding mode, logging every attempt and
   reporting the first match.

The heavy lifting happens in :func:`openssl_encrypt`, which shells out to
``openssl``.  Keeping the RSA handling inside OpenSSL avoids the need for an
external Python crypto dependency and mirrors how the ciphertext was generated
for the assignment this repository accompanies.
"""

import ast
import csv
import os
import subprocess
import tempfile
from functools import lru_cache

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKClTqiJTUa++IPogThEsiNR4J
FpmV12jbfYvEc74ZtyCxGYpt3UcwaYbBoVgBpFepBRnwjJEPX8jxip7yfxr/vqYv
MrQ4LJggKRKUDrWFwuI+lNmxsVz+E4now0v1E/lHa5p8PxdqRBdm1xw4yXx48Xft
rnnCa8w19lq20OSNPwIDAQAB
-----END PUBLIC KEY-----
"""

TARGET_CIPHER_HEX = "9A60E4CE8D70B2A12BB2422D73571A445159955A844AE5EA9995870AA4819BA434835C88AB4F1FBD17712DC525613382FF6A9621CB9BC0F82191EB60AAA369FC061A614C18F81FA9906FB168E0E8B0A0EA5C3A9E6E1566820E4831CAA9BDF0FB048F8095DE65DB6D9FA79AFF7D40529E512ADB91231D176944064200AEC070A1"


_CANDIDATE_FILE = os.path.join(os.path.dirname(__file__), "candidates.txt")


@lru_cache(maxsize=1)
def _load_candidates():
    """Return the tuple of candidate plaintext byte strings loaded from disk."""
    candidates = []
    with open(_CANDIDATE_FILE, 'r', encoding='utf-8') as candidate_file:
        for line in candidate_file:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            parsed = ast.literal_eval(stripped)
            if isinstance(parsed, str):
                parsed = parsed.encode('utf-8')
            elif not isinstance(parsed, bytes):
                raise TypeError(
                    "Candidate values must be str or bytes literals, got {}".format(
                        type(parsed).__name__
                    )
                )
            candidates.append(parsed)
    return tuple(candidates)


def build_candidates():
    """Return a fresh list of candidate plaintext byte strings."""
    return list(_load_candidates())


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
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            return None
        with open(tmp_out.name, "rb") as f:
            return f.read()
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
                    "  Mode {mode} trial {trial}: plaintext too long for this padding mode;"
                    " skipping sample display".format(mode=padding_mode, trial=attempt)
                )
                reproducible[padding_mode] = False
                break
            sample_ciphertexts.append(cipher)
            print(
                "  Mode {mode} trial {trial}: {cipher}".format(
                    mode=padding_mode, trial=attempt, cipher=cipher.hex()
                )
            )
        else:
            unique_ciphertexts = {c for c in sample_ciphertexts}
            if len(unique_ciphertexts) == 1:
                print(
                    "  Mode {mode}: ciphertexts identical across {count} attempts".format(
                        mode=padding_mode, count=samples_per_mode
                    )
                )
                reproducible[padding_mode] = True
            else:
                print(
                    "  Mode {mode}: ciphertexts differ across {count} attempts".format(
                        mode=padding_mode, count=samples_per_mode
                    )
                )
                reproducible[padding_mode] = False
    return reproducible


def run_candidate_search_for_mode(
    padding_mode,
    candidates,
    target,
    modulus_len,
    pubkey_path,
    writer,
    log_file,
    attempt_offset,
    example_attempts_to_print,
    printed_examples,
    notified_log_only,
):
    """Run the brute-force search for a single ``padding_mode``.

    Parameters are passed explicitly so the function remains pure with respect
    to side effects (aside from logging).  The function returns a tuple of
    ``(attempts_used, printed_examples, notified_log_only, match)`` where
    ``match`` is either ``None`` or a ``dict`` describing the successful
    candidate.
    """

    attempts = attempt_offset
    match = None
    for idx, cand in enumerate(candidates, start=1):
        cipher = openssl_encrypt(pubkey_path, cand, modulus_len, padding_mode)
        if cipher is None:
            continue
        attempts += 1
        row = [attempts, idx, padding_mode, repr(cand), cipher.hex()]
        writer.writerow(row)
        log_file.flush()
        if printed_examples < example_attempts_to_print:
            print(",".join(str(value) for value in row))
            printed_examples += 1
            if printed_examples == example_attempts_to_print:
                print("(Further attempts are logged to bruteforce_attempts_log.csv only.)")
        elif not notified_log_only:
            print("(All additional attempts are recorded in bruteforce_attempts_log.csv.)")
            notified_log_only = True
        if cipher == target:
            match = {
                "padding_mode": padding_mode,
                "candidate": cand,
                "attempt_number": attempts,
                "candidate_index": idx,
            }
            break
        if idx % 100 == 0:
            print(
                "Tried {idx} candidates under padding mode {mode} ({attempts} successful"
                " encryptions in this mode)...".format(
                    idx=idx, mode=padding_mode, attempts=attempts
                )
            )
    return attempts, printed_examples, notified_log_only, match


def main():
    """Coordinate the demonstration of deterministic modes and grade search."""

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
            for padding_mode in padding_modes:
                print(f"\n=== Running brute-force attempts for padding mode: {padding_mode} ===")
                attempts, printed_examples, notified_log_only, match = (
                    run_candidate_search_for_mode(
                        padding_mode,
                        candidates,
                        target,
                        modulus_len,
                        pubkey_path,
                        writer,
                        log_file,
                        attempts,
                        example_attempts_to_print,
                        printed_examples,
                        notified_log_only,
                    )
                )
                if match:
                    print("MATCH FOUND!")
                    print("padding mode:", match["padding_mode"])
                    print("candidate index:", match["candidate_index"])
                    print("candidate bytes repr:", repr(match["candidate"]))
                    try:
                        candidate_text = match["candidate"].decode()
                    except UnicodeDecodeError:
                        print("candidate text: (non-utf8)")
                    else:
                        print("candidate text:", candidate_text)
                    return
        print("No match found. Try expanding the candidate list.")
        print(f"Attempt details logged to {log_path} and echoed above.")
    finally:
        if os.path.exists(pubkey_path):
            os.remove(pubkey_path)


if __name__ == "__main__":
    main()
