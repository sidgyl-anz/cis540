# Differences Between Specific Byte Literals

This document explains how several Python byte string literals differ. The patterns below apply equally to other words or digits that you may encode as bytes.  For completeness, a normal (Unicode) string literal such as `'Fail'` is also available in the candidate list.  A plain string evaluates to type `str` and will be UTF-8 encoded by the brute-force script when needed.

## Variants for `b'Fail'`
- `b'Fail'`: four ASCII bytes `0x46 0x61 0x69 0x6c` representing the word "Fail" with no line ending.
- `b'Fail\n'`: adds a single line-feed (LF) byte `0x0a` after "Fail", so it ends with a Unix newline.
- `b'Fail\r\n'`: ends with a carriage-return byte `0x0d` followed by line-feed `0x0a`, the Windows CRLF newline sequence.
- `b"b'Fail'"`: contains the literal characters `b`, `'`, `F`, `a`, `i`, `l`, `'`; it is eight bytes long and represents the text `b'Fail'`.
- `b"b'Fail'\n"`: same as above but with an additional trailing LF byte `0x0a`.
- `b"b'Fail'\r\n"`: same as above but with a trailing CRLF sequence `0x0d 0x0a`.
- `'Fail'`: a Unicode string (type `str`) with no newline.  The script encodes it as UTF-8 when attempting encryption, which produces the same bytes as `b'Fail'`.

## Variants for `b'Pass'`
- `b'Pass'`: four ASCII bytes `0x50 0x61 0x73 0x73` for "Pass" with no newline.
- `b'Pass\n'`: appends an LF byte `0x0a` after "Pass".
- `b'Pass\r\n'`: appends a CRLF sequence `0x0d 0x0a` after "Pass".
- `b"b'Pass'"`: the textual representation of the literal `b'Pass'`, eight bytes long.
- `b"b'Pass'\n"`: same textual representation with a trailing LF.
- `b"b'Pass'\r\n"`: same textual representation with a trailing CRLF sequence.
- `'Pass'`: a Unicode string (type `str`) without a newline.  Encoding it to UTF-8 yields the same bytes as `b'Pass'`.

## Variants for `b'1'`
- `b'1'`: a single ASCII byte `0x31` representing the character `'1'` with no newline.
- `b'1\n'`: the digit `'1'` followed by an LF byte `0x0a`.
- `b'1\r\n'`: the digit `'1'` followed by CRLF `0x0d 0x0a`.
- `b"b'1'"`: the textual representation of the literal `b'1'`, five bytes long.
- `b"b'1'\n"`: the same textual representation with an appended LF byte `0x0a`.
- `b"b'1'\r\n"`: the textual representation with an appended CRLF sequence `0x0d 0x0a`.
- `'1'`: a Unicode string (type `str`).  The script encodes it with UTF-8 before encryption so it maps to the same single byte as `b'1'`.

Across all of these groups, the differences boil down to two factors:

1. Whether the bytes encode the plain word/digit itself or the text of the byte literal (including the leading `b` and quotes).
2. Whether the sequence includes no newline, a Unix-style LF newline, or a Windows-style CRLF newline at the end.
