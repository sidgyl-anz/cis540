#!/usr/bin/env python3
# deterministic_bruteforce.py
# Try deterministic raw-RSA encodings + simple zero-padding variants to match a given ciphertext.
#
# Usage:
#   python3 deterministic_bruteforce.py --pub alice_pub.pem --cipher alice_cipher.bin
# Options:
#   --use-openssl : also call `openssl rsautl -encrypt` for each candidate and compare (slow)
#   --candidates-file FILE : optional file with one candidate per line (appended to built-in candidates)
#
# Notes:
#  - This only works if encryption used NO RANDOMIZED PADDING (raw or deterministic padding).
#  - If professor used PKCS#1 v1.5 or OAEP randomized padding, this will not find a match.

import argparse, subprocess, re, os, binascii, sys
from pathlib import Path

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--pub", required=True, help="Public key PEM file (alice_pub.pem)")
    p.add_argument("--cipher", required=True, help="Target ciphertext (binary)")
    p.add_argument("--use-openssl", action="store_true", help="Also test openssl rsautl encrypt for each candidate (slow)")
    p.add_argument("--candidates-file", help="Extra candidates file (one per line)")
    p.add_argument("--max-trials", type=int, default=1000000, help="Max candidates to try (safety)")
    return p.parse_args()

def extract_pub(pem_path):
    out = subprocess.check_output(["openssl","rsa","-pubin","-in",pem_path,"-text","-noout"], text=True)
    mod_lines = []
    cap = False
    for line in out.splitlines():
        if line.strip().startswith("Modulus:"):
            cap = True
            rest = line.partition("Modulus:")[2].strip()
            if rest:
                mod_lines.append(rest)
            continue
        if cap:
            if line.strip().startswith("Exponent:") or line.strip().startswith("publicExponent:"):
                break
            mod_lines.append(line.strip())
    if not mod_lines:
        raise RuntimeError("Failed to parse modulus from openssl output:\n" + out)
    mod_hex = "".join(re.sub(r"[^0-9A-Fa-f]","", " ".join(mod_lines)))
    mod_hex = mod_hex.lstrip("00")
    n = int(mod_hex, 16)
    # exponent
    e = 65537
    m = re.search(r"Exponent:\s*(\d+)\s*\(0x", out)
    if m:
        e = int(m.group(1))
    nbytes = (n.bit_length()+7)//8
    return n, e, nbytes

def candidates_from_file(path):
    cand = []
    for line in open(path, "r", encoding="utf-8", errors="ignore"):
        s = line.rstrip("\n\r")
        if s: cand.append(s.encode())
    return cand

def build_candidates(extra_file=None):
    cands = []
    # decimal strings 0..100 and newline variants
    for i in range(0, 101):
        s = str(i).encode()
        cands.append(s)
        cands.append(s + b"\n")
        cands.append(s + b"\r\n")
    # single byte values
    for i in range(0, 256):
        cands.append(bytes([i]))
    # leading zeros variations
    for i in range(0, 101):
        s = str(i).encode()
        cands.append(b"0" + s)
        cands.append(b"00" + s)
    # letter grades and small words
    for g in ["A","A+","A-","B","B+","B-","C","D","F","Pass","Fail","100","99","score","grade"]:
        cands.append(g.encode())
        cands.append(g.encode()+b"\n")
    # add extra if provided
    if extra_file:
        cands.extend(candidates_from_file(extra_file))
    # dedupe preserving order
    seen = set(); uniq=[]
    for b in cands:
        if b in seen: continue
        seen.add(b); uniq.append(b)
    return uniq

def int_encodings(msg_bytes, nbytes):
    """Return list of (desc, m_int) for different deterministic encodings."""
    res = []
    # raw
    m_raw = int.from_bytes(msg_bytes, "big")
    res.append(("raw", m_raw))
    # left-zero-padded to modulus length
    if len(msg_bytes) <= nbytes:
        pad_left = b"\x00"*(nbytes - len(msg_bytes)) + msg_bytes
        res.append(("left_zero_padded", int.from_bytes(pad_left, "big")))
        # right-zero-padded
        pad_right = msg_bytes + b"\x00"*(nbytes - len(msg_bytes))
        res.append(("right_zero_padded", int.from_bytes(pad_right, "big")))
    # 4-byte int big/little
    if len(msg_bytes) <= 4:
        # big-endian 4 bytes
        be4 = msg_bytes.rjust(4, b"\x00")
        le4 = msg_bytes.ljust(4, b"\x00") if False else msg_bytes.rjust(4, b"\x00")[::-1]  # safer: explicit conversion below
        res.append(("4byte_big", int.from_bytes(be4, "big")))
        res.append(("4byte_little", int.from_bytes(be4, "little")))
    # 2-byte int big/little
    if len(msg_bytes) <= 2:
        be2 = msg_bytes.rjust(2, b"\x00")
        res.append(("2byte_big", int.from_bytes(be2, "big")))
        res.append(("2byte_little", int.from_bytes(be2, "little")))
    return res

def pow_mod_to_bytes(m_int, e, n, nbytes):
    if m_int >= n:
        return None
    c_int = pow(m_int, e, n)
    return c_int.to_bytes(nbytes, "big")

def openssl_rsautl_encrypt(msg_bytes, pub_pem, outtmp="tmp_openssl_out.bin"):
    # write msg to tmp
    with open("tmp_msg.bin","wb") as f: f.write(msg_bytes)
    try:
        subprocess.run(["openssl","rsautl","-encrypt","-pubin","-inkey",pub_pem,"-in","tmp_msg.bin","-out",outtmp], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        data = open(outtmp,"rb").read()
        os.remove(outtmp)
        return data
    except Exception:
        # cleanup if exists
        if os.path.exists(outtmp): os.remove(outtmp)
        return None
    finally:
        if os.path.exists("tmp_msg.bin"): os.remove("tmp_msg.bin")

def main():
    args = parse_args()
    pub = args.pub; cipher_file = args.cipher
    if not os.path.exists(pub):
        print("Public key not found:", pub); sys.exit(2)
    if not os.path.exists(cipher_file):
        print("Cipher file not found:", cipher_file); sys.exit(2)
    n,e,nbytes = extract_pub(pub)
    target = open(cipher_file,"rb").read()
    if len(target) != nbytes:
        print(f"Warning: ciphertext length {len(target)} != modulus bytes {nbytes}")
    print(f"Modulus: {n.bit_length()} bits ({nbytes} bytes), e={e}")
    candidates = build_candidates(args.candidates_file)
    print(f"Total candidates to try: {len(candidates)}")
    tried = 0
    for msg in candidates:
        tried += 1
        if tried > args.max_trials:
            print("Reached max trials limit."); break
        encs = int_encodings(msg, nbytes)
        for desc, m_int in encs:
            cbytes = pow_mod_to_bytes(m_int, e, n, nbytes)
            if cbytes is None: continue
            if cbytes == target:
                print("MATCH FOUND!")
                print("candidate bytes repr:", repr(msg))
                try:
                    print("candidate text:", msg.decode())
                except:
                    print("candidate text: (non-utf8)")
                print("encoding used:", desc)
                print("Stop. You recovered the plaintext.")
                return
        # optionally try openssl rsautl path (slow)
        if args.use_openssl:
            c_os = openssl_rsautl_encrypt(msg, pub)
            if c_os is not None and c_os == target:
                print("MATCH FOUND using openssl rsautl!")
                print("candidate bytes repr:", repr(msg))
                try: print("candidate text:", msg.decode())
                except: print("candidate text: (non-utf8)")
                print("Stop. You recovered the plaintext (via openssl).")
                return
        # progress log
        if tried % 500 == 0:
            print(f"tried {tried} candidates...")
    print("Done: no match found in candidate set. Try expanding candidates or check that encryption used deterministic/raw mode.")

if __name__ == "__main__":
    main()
