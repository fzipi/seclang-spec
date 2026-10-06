# 07. Transformations

One section per transformation. Phase 1 contains the single worked example; the rest of
the Core set arrives in Phase 3 together with the imported SecRules Test Set cases.

### base64Decode

**Status:** Core

**Syntax.** `t:base64Decode`

**Semantics.** Decodes the input as standard Base64 (RFC 4648 section 4, alphabet
`A-Z a-z 0-9 + /`, `=` padding). For a well-formed, correctly padded input the output is
the decoded bytes; decoded NUL bytes are preserved. The empty input produces the empty
output and reports no change. A NUL byte in the *input* terminates it: nothing after
the first NUL is decoded.

Behaviour on malformed input is **not specified** in this version; see the divergence
notes. Compare `base64DecodeExt`, which skips characters outside the alphabet.

**Divergence notes.** The engines disagree on malformed input, so the tests only cover
well-formed input until a Divergence ADR settles it:

- ModSecurity v2 (`apr_base64_decode`) and Coraza (`internal/transformations/
  base64decode.go`) decode up to the first byte outside the alphabet and discard the
  rest; Coraza additionally ignores `\r` and `\n`.
- libmodsecurity v3 (`src/utils/base64.cc`, mbedtls) rejects the whole input on any
  byte outside the alphabet, on a length that is not a multiple of four (missing
  padding) and on padding followed by data, leaving the value unchanged; it ignores
  `\n` and `\r\n`.

**Tests.** `tests/unit/transformations/base64Decode.json`
