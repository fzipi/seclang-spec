# 07. Transformations

One section per transformation. Phase 1 contains the single worked example; the rest of
the Core set arrives in Phase 3 together with the imported SecRules Test Set cases.

### base64Decode

**Status:** Core

**Syntax.** `t:base64Decode`

**Semantics.** Decodes the input as standard Base64 (RFC 4648 section 4, alphabet
`A-Z a-z 0-9 + /`, `=` padding). Decoding proceeds from the start of the input and
stops at the first byte that is not in the alphabet or padding; bytes after that point
are discarded. Missing padding is tolerated. Decoded NUL bytes are preserved in the
output. The empty input decodes to the empty output and reports no change.

Compare `base64DecodeExt`, which skips characters outside the alphabet instead of
stopping at them.

**Divergence notes.** None known.

**Tests.** `tests/unit/transformations/base64Decode.json`
