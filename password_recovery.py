#!/usr/bin/env python3
"""Utilities to help recover simple password hashes used in coursework."""

from __future__ import annotations

import argparse
import hashlib
import string
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional, Sequence

try:
    import crypt  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - crypt is expected on Linux only
    crypt = None

CandidateFilter = Callable[[str], bool]


def iter_candidates(
    dictionary_files: Iterable[Path], *, candidate_filter: Optional[CandidateFilter] = None
) -> Iterable[str]:
    for dictionary_path in dictionary_files:
        with dictionary_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                word = line.strip()
                if word and (candidate_filter is None or candidate_filter(word)):
                    yield word


def md5_hint_filter(candidate: str) -> bool:
    """Filter enforcing the MD5 hint (5 chars, alnum + common punctuation)."""

    allowed = set(string.ascii_letters + string.digits + string.punctuation)
    return len(candidate) == 5 and all(char in allowed for char in candidate)


def sha_hint_filter(candidate: str) -> bool:
    """Filter enforcing the SHA-1/256 hint (7 alphanumeric characters)."""

    return len(candidate) == 7 and candidate.isalnum()


def recover_hash(
    hash_value: str,
    dictionary_files: Iterable[Path],
    digest: Callable[[bytes], hashlib._Hash],
    *,
    respect_hints: bool,
    hint_filter: CandidateFilter,
) -> Optional[str]:
    """Attempt to recover a digest using dictionary candidates."""

    candidate_filter = hint_filter if respect_hints else None

    for candidate in iter_candidates(dictionary_files, candidate_filter=candidate_filter):
        if digest(candidate.encode()).hexdigest() == hash_value:
            return candidate
    return None


def recover_bcrypt(
    hash_value: str, dictionary_files: Iterable[Path], *, respect_hints: bool
) -> Optional[str]:
    if crypt is None:
        raise SystemExit("The Python 'crypt' module is required on Linux to verify bcrypt hashes.")

    common_passwords = [
        "123456",
        "password",
        "123456789",
        "12345",
        "qwerty",
        "abc123",
        "football",
        "letmein",
        "admin",
        "welcome",
    ]

    if respect_hints:
        for candidate in common_passwords:
            if crypt.crypt(candidate, hash_value) == hash_value:
                return candidate
        candidate_filter = None
    else:
        candidate_filter = None

    for candidate in iter_candidates(dictionary_files, candidate_filter=candidate_filter):
        if crypt.crypt(candidate, hash_value) == hash_value:
            return candidate
    return None


@dataclass(frozen=True)
class HashcatPreset:
    """Describe how to invoke hashcat for a specific algorithm."""

    mode: int
    attack: int
    description: str
    command_builder: Callable[[str, Optional[str]], str]


def _md5_command(hash_value: str, _wordlist: Optional[str]) -> str:
    return (
        "hashcat -m 0 -a 3 "
        f"{hash_value} ?1?1?1?1?1 "
        "-1 ?l?u?d?s"
    )


def _sha256_command(hash_value: str, wordlist: Optional[str]) -> str:
    if wordlist:
        return f"hashcat -m 1400 -a 0 {hash_value} {wordlist}"
    return (
        "hashcat -m 1400 -a 3 "
        f"{hash_value} ?1?1?1?1?1?1?1 "
        "-1 ?l?u?d"
    )


def _sha1_command(hash_value: str, wordlist: Optional[str]) -> str:
    if wordlist:
        return f"hashcat -m 100 -a 0 {hash_value} {wordlist}"
    return (
        "hashcat -m 100 -a 3 "
        f"{hash_value} ?1?1?1?1?1?1?1 "
        "-1 ?l?u?d"
    )


def _bcrypt_command(hash_value: str, wordlist: Optional[str]) -> str:
    if not wordlist:
        raise SystemExit(
            "bcrypt hashes are slow to brute-force. Provide --wordlist to run "
            "a dictionary attack (for example, the rockyou wordlist)."
        )
    return f"hashcat -m 3200 -a 0 '{hash_value}' {wordlist}"


PRESETS: Dict[str, HashcatPreset] = {
    "md5": HashcatPreset(
        mode=0,
        attack=3,
        description="MD5 brute-force with alphanumeric + symbol charset",
        command_builder=_md5_command,
    ),
    "sha1": HashcatPreset(
        mode=100,
        attack=0,
        description="SHA-1 dictionary attack (fallback to 7-char mask)",
        command_builder=_sha1_command,
    ),
    "sha256": HashcatPreset(
        mode=1400,
        attack=0,
        description="SHA-256 dictionary attack (fallback to 7-char mask)",
        command_builder=_sha256_command,
    ),
    "bcrypt": HashcatPreset(
        mode=3200,
        attack=0,
        description="bcrypt dictionary attack",
        command_builder=_bcrypt_command,
    ),
}


def suggest_hashcat_command(algorithm: str, hash_value: str, wordlist: Optional[str]) -> None:
    preset = PRESETS[algorithm]
    command = preset.command_builder(hash_value, wordlist)
    print("# Suggested hashcat invocation")
    print(f"# Mode: {preset.mode} (algorithm), Attack: {preset.attack}")
    print(command)


@dataclass(frozen=True)
class ExampleCase:
    """Built-in example to validate the helper with known passwords."""

    label: str
    algorithm: str
    hash_value: str
    expected_password: str
    candidates: Sequence[str]
    respect_hints: bool = True


EXAMPLE_CASES: Sequence[ExampleCase] = (
    ExampleCase(
        label="MD5 example (birhanu)",
        algorithm="md5",
        hash_value="6fb3540ce7dc22563bf5655328fab793",
        expected_password="birhanu",
        candidates=("password", "birhanu", "CIS540"),
        respect_hints=False,
    ),
    ExampleCase(
        label="MD5 assignment hash",
        algorithm="md5",
        hash_value="801338b11e9d13070dc726cbc67ab160",
        expected_password="f!r5t",
        candidates=("f!r5t", "birhanu", "CIS540"),
    ),
    ExampleCase(
        label="SHA-256 example (birhanu)",
        algorithm="sha256",
        hash_value="ee4dd2b71a00c9a4952f1f3856d96840b4a4f86de268ed47485add13ceb67846",
        expected_password="birhanu",
        candidates=("birhanu",),
    ),
    ExampleCase(
        label="bcrypt example (birhanu)",
        algorithm="bcrypt",
        hash_value="$2b$12$2D.0g8MKhJCFNNplEgvWfeGKkk9xy7uq9rZ0KWFrtnX0hMqEpbdQi",
        expected_password="birhanu",
        candidates=("birhanu", "CIS540", "password"),
    ),
    ExampleCase(
        label="bcrypt assignment hash",
        algorithm="bcrypt",
        hash_value="$2b$12$O64GAcboleHTqpDeCMwQJe7IwT.6AE1ycBJZGKQGt5EZJv1MoVCt.",
        expected_password="123456789",
        candidates=("password", "123456", "123456789", "birhanu"),
    ),
)


def run_examples() -> None:
    """Execute the provided examples to validate the helper locally."""

    print("# Running built-in examples with temporary dictionaries")
    for case in EXAMPLE_CASES:
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            for candidate in case.candidates:
                handle.write(candidate + "\n")
            temp_path = Path(handle.name)

        try:
            if case.algorithm == "md5":
                result = recover_hash(
                    case.hash_value,
                    [temp_path],
                    hashlib.md5,
                    respect_hints=case.respect_hints,
                    hint_filter=md5_hint_filter,
                )
            elif case.algorithm == "sha1":
                result = recover_hash(
                    case.hash_value,
                    [temp_path],
                    hashlib.sha1,
                    respect_hints=case.respect_hints,
                    hint_filter=sha_hint_filter,
                )
            elif case.algorithm == "sha256":
                result = recover_hash(
                    case.hash_value,
                    [temp_path],
                    hashlib.sha256,
                    respect_hints=case.respect_hints,
                    hint_filter=sha_hint_filter,
                )
            elif case.algorithm == "bcrypt":
                result = recover_bcrypt(
                    case.hash_value,
                    [temp_path],
                    respect_hints=case.respect_hints,
                )
            else:
                print(f"- {case.label}: unsupported algorithm {case.algorithm}")
                continue

            if result:
                status = "OK" if result == case.expected_password else "MISMATCH"
                print(
                    f"- {case.label}: recovered '{result}' (expected '{case.expected_password}') [{status}]"
                )
            else:
                print(f"- {case.label}: no match found with sample dictionary")
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:  # pragma: no cover - best effort cleanup
                pass


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    md5_parser = subparsers.add_parser("md5", help="Dictionary attack for MD5 hashes")
    md5_parser.add_argument("hash", help="MD5 hash to crack")
    md5_parser.add_argument(
        "dictionaries",
        nargs="+",
        type=Path,
        help="Dictionary files to use for the attack (one candidate per line)",
    )
    md5_parser.add_argument(
        "--ignore-hints",
        action="store_true",
        help="Allow candidates that are not 5 characters of letters/digits/punctuation",
    )

    sha1_parser = subparsers.add_parser("sha1", help="Dictionary attack for SHA-1 hashes")
    sha1_parser.add_argument("hash", help="SHA-1 hash to crack")
    sha1_parser.add_argument(
        "dictionaries",
        nargs="+",
        type=Path,
        help="Dictionary files to use for the attack (one candidate per line)",
    )
    sha1_parser.add_argument(
        "--ignore-hints",
        action="store_true",
        help="Allow candidates that are not 7 alphanumeric characters",
    )

    sha256_parser = subparsers.add_parser(
        "sha256", help="Dictionary attack for SHA-256 hashes (same hint as SHA-1)"
    )
    sha256_parser.add_argument("hash", help="SHA-256 hash to crack")
    sha256_parser.add_argument(
        "dictionaries",
        nargs="+",
        type=Path,
        help="Dictionary files to use for the attack (one candidate per line)",
    )
    sha256_parser.add_argument(
        "--ignore-hints",
        action="store_true",
        help="Allow candidates that are not 7 alphanumeric characters",
    )

    bcrypt_parser = subparsers.add_parser("bcrypt", help="Dictionary attack for bcrypt hashes")
    bcrypt_parser.add_argument("hash", help="Bcrypt hash to crack")
    bcrypt_parser.add_argument(
        "dictionaries",
        nargs="+",
        type=Path,
        help="Dictionary files to use for the attack",
    )
    bcrypt_parser.add_argument(
        "--ignore-hints",
        action="store_true",
        help="Skip the built-in check of the most common passwords",
    )

    hashcat_parser = subparsers.add_parser(
        "hashcat", help="Print suggested hashcat commands for the coursework hashes"
    )
    hashcat_parser.add_argument(
        "algorithm",
        choices=sorted(PRESETS.keys()),
        help="Hash algorithm to target",
    )
    hashcat_parser.add_argument("hash", help="Hash to recover")
    hashcat_parser.add_argument(
        "--wordlist",
        help="Optional path to a dictionary for dictionary attacks",
    )

    subparsers.add_parser(
        "examples",
        help="Run built-in examples using the hashes and hints from the assignment",
    )

    args = parser.parse_args(argv)

    if args.mode == "md5":
        result = recover_hash(
            args.hash,
            args.dictionaries,
            hashlib.md5,
            respect_hints=not args.ignore_hints,
            hint_filter=md5_hint_filter,
        )
        if result:
            print(f"Recovered MD5 password: {result}")
        else:
            print("Password not recovered with provided dictionaries.")
    elif args.mode == "sha1":
        result = recover_hash(
            args.hash,
            args.dictionaries,
            hashlib.sha1,
            respect_hints=not args.ignore_hints,
            hint_filter=sha_hint_filter,
        )
        if result:
            print(f"Recovered SHA-1 password: {result}")
        else:
            print("Password not recovered with provided dictionaries.")
    elif args.mode == "sha256":
        result = recover_hash(
            args.hash,
            args.dictionaries,
            hashlib.sha256,
            respect_hints=not args.ignore_hints,
            hint_filter=sha_hint_filter,
        )
        if result:
            print(f"Recovered SHA-256 password: {result}")
        else:
            print("Password not recovered with provided dictionaries.")
    elif args.mode == "bcrypt":
        result = recover_bcrypt(args.hash, args.dictionaries, respect_hints=not args.ignore_hints)
        if result:
            print(f"Recovered bcrypt password: {result}")
        else:
            print("Password not recovered with provided dictionaries.")
    elif args.mode == "hashcat":
        suggest_hashcat_command(args.algorithm, args.hash, args.wordlist)
    elif args.mode == "examples":
        run_examples()
    else:  # pragma: no cover - subparsers enforce valid choices
        parser.error(f"Unsupported mode {args.mode}")


if __name__ == "__main__":
    main()
