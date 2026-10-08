# Lean Formalization Spike — Design

Status: approved in conversation, 2026-10-08 (brief:
`docs/superpowers/specs/2026-10-08-lean-formalization-brief.md`).

## 1. Brief

**You said.** Start the Lean formalization spike: five transformations as Lean
definitions, a runner over the unit-tier corpus, and a verdict on whether the approach
pays off before any chapter is committed to it.

**Agreed.** A Lake project under `formal/` with no dependencies beyond the Lean toolchain,
defining `lowercase`, `hexEncode`, `urlDecodeUni`, `cssDecode` and `base64Decode` over
`ByteArray`, and a `lake exe seclang-check` that reads
`tests/unit/transformations/*.json`, runs every case whose transformation is formalized,
and exits non-zero on any mismatch. CI builds and runs it. The formalization is a
reference, not an engine: no `compat/known-gaps.md` rows, every mismatch is resolved
before merge.

**Assumptions.**

- The reference semantics is ModSecurity v2 (`apache2/msc_util.c`, `v2/master` 2026-09),
  which is what the corpus expects; where the spec prose is silent or wrong relative to
  the corpus, the spec is fixed in the same branch (that is the point of the spike).
- Lean `v4.34.1` (current stable), pinned in `formal/lean-toolchain`; `Std` and
  `Lean.Json` come with the toolchain, nothing is vendored.
- No proofs in this spike beyond `#guard` smoke checks; proofs arrive with the processing
  model.

## 2. Shape

```
formal/
  lean-toolchain              leanprover/lean4:v4.34.1
  lakefile.toml               lib SecLang, exe seclang-check (root Main)
  .gitignore                  .lake/
  README.md                   how to build and run; what a mismatch means
  SecLang.lean                imports
  SecLang/Transformations.lean   byte helpers + the five definitions, each with #guard
  Main.lean                   corpus runner
```

CI: `.github/workflows/validate.yml` gains a `lean` job using `leanprover/lean-action`
pinned to the v1.6.1 commit (`f061402b660e0c34644504b324e830f2991d4865`), with
`lake-package-directory: formal`, followed by `lake exe seclang-check` run from `formal/`.

## 3. Definitions

All five are `ByteArray → ByteArray`, written as explicit index loops (`partial def` or
structural recursion on a fuel index) so the generated code is readable next to the C.

| Definition | Semantics modelled | Source |
|---|---|---|
| `lowercase` | `A`–`Z` → `a`–`z`, other bytes unchanged | `spec/07#lowercase` |
| `hexEncode` | each byte → two lowercase hex digits | `spec/07#hexencode` |
| `urlDecodeUniWith (map : Nat → Option UInt8)` | `+` → space; `%XX` with two hex digits → byte; `%uXXXX` with four hex digits → `map code` if some, else the low byte, plus `0x20` when the high byte is `0xFF` and the low byte is in `0x01`–`0x5E`; anything else copied verbatim (`%u` as two bytes) | `msc_util.c` `urldecode_uni_nonstrict_inplace_ex` |
| `urlDecodeUni` | `urlDecodeUniWith (fun _ => none)` (no `SecUnicodeMapFile`) | `spec/07#urldecodeuni` |
| `cssDecode` | `\` + 1–6 hex digits → the low byte of the code point, plus `0x20` when the escape has 4–6 digits, the two digits before the last two are `ff`, and (for 5–6 digits) the leading digits are zero, and the low byte is in `0x01`–`0x5E`; one following C-`isspace` byte is consumed; `\` + newline → nothing; `\` + other byte → that byte; trailing `\` → nothing | `msc_util.c` `css_decode_inplace` |
| `base64Decode` | input truncated at the first NUL; standard alphabet; decoding stops at the first byte outside the alphabet (`=` included); complete quanta of 4 emit 3 bytes, a trailing 2 or 3 characters emit 1 or 2 bytes, a trailing single character emits nothing | `spec/07#base64decode`; malformed-input choice follows v2/Coraza (noted in code) |

`ret` is not modelled: the runner computes `output != input` as the data contract says.

## 4. Runner

`lake exe seclang-check [dir]` (default `../tests/unit/transformations`, i.e. run from
`formal/`). For each `*.json` file in name order:

1. Parse with `Lean.Json`; each element has `name`, `input`, `output`, `ret`.
2. If `name` is not in the formalized table, print `name.json: skipped (not formalized)`.
3. Otherwise convert `input` to bytes (each code point must be ≤ 255, else the file is a
   failure: the corpus violated `tests/README.md`), run the definition, convert back, and
   compare `output` and `ret`.
4. Print `name.json: N passed, M failed`, then one line per mismatch in the adapters'
   wording: `t:name on "input": output "got", expected "want"`, with strings shown via
   `String.quote`.

Exit code 1 when any case failed or any file could not be read or parsed; 0 otherwise.
No known-gaps handling.

## 5. Spec fixes the model forces

Reading the C against the prose while writing the definitions already shows one defect:
`spec/07-transformations.md#cssdecode` says a hex escape "becomes the character", but the
corpus requires the low byte with full-width folding (`\ff01` → `!`), which the prose
never mentions. The spike rewrites that paragraph to state the byte-level rule, the
`isspace` set, and the full-width fold. Any further mismatch the runner reports is
classified per `AGENTS.md` ("When an adapter run disagrees with the spec") and fixed in
the same branch.

## 6. Repository integration

- `AGENTS.md`: a `formal/` row in the layout table and the `lake` commands in "Before you
  commit".
- `README.md`: a `formal/` row in the layout table.
- `tools/validate.py`: unchanged; `formal/` is outside its scope.
- `site/`: unchanged; `formal/` is not published.

## 7. Verdict criteria

The spike pays off if (a) all 51 cases pass after the classified fixes, and (b) the
definitions surfaced at least one spec ambiguity the English hid. Both are reported in
the final branch summary, with the recommendation on stage 1 (all 35 transformation
files).
