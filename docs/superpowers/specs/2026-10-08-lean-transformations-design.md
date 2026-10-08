# Lean Formalization, Stage 1: All Transformations — Design

Status: approved in conversation, 2026-10-08 ("Looks great, continue!" after the spike;
stage list in `docs/superpowers/specs/2026-10-08-lean-formalization-brief.md` §1).

## 1. Brief

**You said.** Continue with the next stage: all 35 transformation files, making
`spec/07-transformations.md` the first fully formal chapter.

**Agreed.** Extend `formal/` with the 30 remaining transformations (363 corpus cases in
total), each a `ByteArray → ByteArray` definition with `#guard` checks, and register them
in the runner so `lake exe seclang-check` reports no skipped file. Every disagreement the
definitions expose between the prose, the corpus and the engines is resolved in the same
branch, as in the spike: spec text fixed, corpus cases excluded through the importer, or
known-gaps rows added with source pointers. No dependency is added: MD5 and SHA-1 are
written in Lean.

**Assumptions.**

- Reference semantics stays ModSecurity v2 `apache2/msc_util.c` and `apache2/re_tfns.c`
  (`v2/master`, 2026-09), cross-checked against libmodsecurity v3.0.16
  (`src/actions/transformations/*.cc`) and Coraza v3.8.1
  (`internal/transformations/*.go`) wherever the prose is silent.
- The corpus expectation wins over the prose when every engine agrees with the corpus
  (the prose is then fixed); the prose wins over an engine when the engines disagree
  among themselves (a known-gaps row or a divergence note records the loser).
- `ret` is checked as `output != input`, as fixed in the spike.

## 2. Shape

```
formal/SecLang/Bytes.lean             byte helpers moved out of Transformations.lean (byteAt, hexVal, hexAt, isSpace, hexDigit)
formal/SecLang/Digest.lean            md5, sha1 over ByteArray (RFC 1321, RFC 3174), guards on the standard test vectors
formal/SecLang/Transformations.lean   all 35 definitions, grouped Core then Extended, each citing its C function
formal/SecLang.lean                   imports
formal/Main.lean                      `formalized` table lists all 35 names
formal/README.md                      status: all transformations
```

## 3. Definitions and the spec they force

Every definition is an explicit byte loop. Where the prose and the engines disagree, the
table says which wins and what changes in the repository.

| Definition | Finding | Resolution |
|---|---|---|
| `uppercase`, `removeNulls`, `replaceNulls`, `removeWhitespace`, `trim*`, `length`, `urlDecode`, `urlEncode`, `sqlHexDecode`, `base64Encode`, `replaceComments`, `escapeSeqDecode`, `htmlEntityDecode`, `normalisePath`, `normalisePathWin`, `md5`, `sha1` | prose and engines agree | none |
| `compressWhitespace` | v2 (`NBSP`) and Coraza (`rawNBSP`) treat byte `0xA0` as whitespace; v3 (`isspace`) does not; the prose lists ASCII only | prose: `0xA0` is whitespace (as `removeWhitespace`); new `tests/unit/transformations/compressWhitespace-extra.json`; known-gaps row for libmodsecurity v3 |
| `cmdLine` | all engines collapse exactly space, `,`, `;`, HT, CR, LF; VT and FF are ordinary bytes; v2 stops at a NUL byte (C string), v3 and Coraza do not | prose lists the exact set; divergence note for v2 (no test: a NUL case would need a v2 adapter) |
| `jsDecode` | all engines decode `\a` to BEL | prose adds `\a` |
| `removeCommentsChar` | all engines also remove `<!--` and `-->` | prose adds them |
| `removeComments` (Extended) | all engines copy the byte that follows `*/` or `-->` verbatim, which at end of input is the C terminator, so `/* x */` yields one NUL byte (corpus expects it); `--` and `#` truncate the value | prose states both |
| `hexDecode` (Extended) | v2 and v3 decode every pair with digit arithmetic that gives garbage for non-hex bytes (`0z` → `#`), and the corpus expects the garbage; the prose says they stop at a non-hex byte | prose: pairs are decoded, a trailing odd byte is dropped, a non-hex byte is unspecified; the two garbage cases join `EXCLUDED_CASES` (keyed by input); the Coraza known-gaps row shrinks to one case (odd length) |
| `parityEven7bit`, `parityOdd7bit` (Extended) | v2 and v3 compute parity over all eight bits and then set or clear bit 7, so a byte whose high bit is set may keep odd parity | prose states the eight-bit rule |
| `base64DecodeExt` (Extended) | v2 ignores `=`, skips every other non-alphabet byte, stops at NUL; a `=` after a single dangling sextet makes v2 return the empty value | prose: ignore `=`, skip others, stop at NUL; the dangling-sextet quirk is noted as unspecified |
| `utf8toUnicode` | v2 consumes a NUL plus the next byte as a two-byte sequence when that byte is ≥ `0x80`; v3 drops a NUL that is not last; Coraza leaves NUL alone, as the prose says | model follows the prose; divergence note names both quirks (no test: v3's row would need a v3 run this session cannot do, and the quirk is not reachable from CRS inputs) |

`removeComments` also returns one space for an unterminated comment, and `hexDecode`'s
`ret` is `output != input` like every other transformation.

## 4. Runner and corpus changes

- `Main.lean`: `formalized` gains the 30 names; `compressWhitespace-extra.json` is picked
  up by name like every file.
- `tools/import_sts.py`: `EXCLUDED_CASES` entries may be keyed by `(name, input)` for
  transformation cases (they have no `param`); `convert_case` checks both keys. Test in
  `tools/test_import_sts.py`. `hexDecode.json` regenerated.
- `compat/known-gaps.md`: the hexDecode Coraza row becomes "(one case)"; a new row
  `compressWhitespace-extra.json` / libmodsecurity v3 / "byte 0xA0 is not whitespace
  (`isspace`, `compress_whitespace.cc`)". The Coraza adapter is run locally; the v3 row
  is verified by CI.

## 5. Repository integration

- `README.md` and `AGENTS.md`: the `formal/` rows drop "spike stage"; `formal/README.md`
  says every transformation is covered.
- `spec/07-transformations.md`: the preamble sentence says the Lean definitions cover the
  whole chapter.
- Site, validator, matrix: unchanged beyond the prose edits (anchors are stable).

## 6. Verdict criteria

Done when `lake exe seclang-check` prints 36 files with zero failures and zero skips
(35 generated or hand-maintained files plus `compressWhitespace-extra.json`),
`tools/validate.py` is at 0 errors, the Coraza adapter is green with the updated known-gaps
rows, and every row of §3 is reflected in the spec text.

## 7. Corrections from the whole-branch review

A differential run of the compiled v2 functions against the Lean definitions corrected
four rows of §3:

- `normalisePathWin`: v2 and v3 convert only the current and next byte, keeping a backslash
  reached while skipping a slash run; the model follows the prose (convert all). Divergence
  note, `normalisePathWin-extra.json`, v3 known-gaps row.
- `utf8toUnicode`: every engine emits five digits above U+FFFF (the prose said four); v3 and
  Coraza do not leave malformed bytes unchanged. Prose corrected, divergence notes
  extended, `utf8toUnicode-extra.json` with v3 and Coraza known-gaps rows.
- `base64DecodeExt`: v3 and Coraza skip NUL; only v2 stops. The model and the prose now skip
  it.
- `sqlHexDecode`: the model matches v3, not v2 (v2 copies the byte after a literal unchecked
  and truncates at a decoded NUL). Docstring and prose say so.
- `compressWhitespace` is a Core semantics change and got ADR-0026.
