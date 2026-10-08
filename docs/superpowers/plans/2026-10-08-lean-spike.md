# Lean Formalization Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Lake project at `formal/` defining five transformations over `ByteArray` and a `lake exe seclang-check` that runs the unit-tier corpus against them, green in CI, with every mismatch resolved as a spec, corpus or model fix.

**Architecture:** `SecLang/Transformations.lean` holds byte helpers and the five definitions, each pinned by `#guard` checks that act as unit tests at compile time. `Main.lean` is the runner: it loads each `tests/unit/transformations/*.json` with core `Lean.Json`, converts byte strings to `ByteArray`, and prints per-file pass/fail in the adapters' wording. No dependencies beyond the toolchain.

**Tech Stack:** Lean `v4.34.1` via elan (`~/.elan/bin` must be on `PATH`), Lake 5 with `lakefile.toml`, `leanprover/lean-action` in CI.

**Spec:** `docs/superpowers/specs/2026-10-08-lean-spike-design.md`; brief `docs/superpowers/specs/2026-10-08-lean-formalization-brief.md`; data contract `tests/README.md`; reference C in `~/Workspace/OWASP/modsecurity/modsecurity` (`git show v2/master:apache2/msc_util.c`).

## Global Constraints

- `formal/lean-toolchain` is exactly `leanprover/lean4:v4.34.1`; no `require` in `lakefile.toml`.
- Definitions are `ByteArray → ByteArray`, explicit index loops, `termination_by b.size - i` where lookahead recursion is used; no tactics beyond what `decreasing_by` defaults and `#guard` need.
- Reference semantics is ModSecurity v2 `apache2/msc_util.c` (`v2/master`, 2026-09); every deviation from the spec prose it reveals is fixed in `spec/07-transformations.md` in this branch, never in `compat/known-gaps.md`.
- Byte strings: each JSON code point is one byte; a code point above 255 is a corpus error reported as a failure, never silently truncated.
- `ret` is checked as `(output != input) == (ret == 1)`.
- Every commit passes `lake build` from `formal/` and `uv run python tools/validate.py` (0 errors). Commit messages end with the two attribution lines used throughout the repository.
- Never push.

## Review Focus

1. `%u` followed by fewer than four bytes (`%u00` at end of input). Expected: `%u00` copied verbatim; pinned by `#guard` in Task 2 (corpus `%u00%u0020`).
2. A hex escape of exactly six digits followed by a seventh hex digit (`\1234567`). Expected: six consumed, `7` literal; `#guard` in Task 3.
3. A backslash before a whitespace byte (`\ ` then space). Expected: the backslash escapes the space, the following space is kept (only hex escapes consume whitespace); `#guard` in Task 3.
4. A Base64 input whose length is not a multiple of four without padding (`VGVzdENhc2U`). Expected: `TestCase` (trailing 3 sextets emit 2 bytes); `#guard` in Task 4.
5. A corpus file containing a byte-string violation (code point > 255). Expected: the runner reports the file as failed with the offending string, exit 1; checked manually in Task 5 with a scratch file.

---

### Task 1: Project skeleton, `lowercase`, `hexEncode`

**Files:**
- Create: `formal/lean-toolchain`, `formal/lakefile.toml`, `formal/.gitignore`, `formal/SecLang.lean`, `formal/SecLang/Transformations.lean`, `formal/Main.lean` (stub)

**Interfaces:**
- Produces: `SecLang.lowercase`, `SecLang.hexEncode : ByteArray → ByteArray`; helpers `SecLang.byteAt : ByteArray → Nat → Option UInt8`, `SecLang.hexVal : UInt8 → Option UInt8`, `SecLang.hexAt : ByteArray → Nat → Option UInt8`, `SecLang.isSpace : UInt8 → Bool`.

- [ ] **Step 1: Scaffold**

```sh
mkdir -p formal/SecLang
printf 'leanprover/lean4:v4.34.1\n' > formal/lean-toolchain
printf '.lake/\n' > formal/.gitignore
cat > formal/lakefile.toml <<'EOF'
name = "seclang"
defaultTargets = ["seclang-check"]

[[lean_lib]]
name = "SecLang"

[[lean_exe]]
name = "seclang-check"
root = "Main"
EOF
printf 'import SecLang.Transformations\n' > formal/SecLang.lean
printf 'import SecLang\n\ndef main (_ : List String) : IO UInt32 := return 0\n' > formal/Main.lean
```

- [ ] **Step 2: Failing guards** — `formal/SecLang/Transformations.lean`:

```lean
/-!
# Transformations (`spec/07-transformations.md`)

Executable reference definitions over byte arrays. Reference semantics: ModSecurity v2
`apache2/msc_util.c` (`v2/master`, 2026-09), which is what the unit-tier corpus expects.
-/
namespace SecLang

/-- The byte at `i`, or `none` past the end. -/
def byteAt (b : ByteArray) (i : Nat) : Option UInt8 :=
  if h : i < b.size then some b[i] else none

/-- Value of an ASCII hexadecimal digit. -/
def hexVal (b : UInt8) : Option UInt8 :=
  if 48 ≤ b && b ≤ 57 then some (b - 48)        -- 0-9
  else if 65 ≤ b && b ≤ 70 then some (b - 55)   -- A-F
  else if 97 ≤ b && b ≤ 102 then some (b - 87)  -- a-f
  else none

/-- The hexadecimal digit at `i`, when there is one. -/
def hexAt (b : ByteArray) (i : Nat) : Option UInt8 := byteAt b i >>= hexVal

/-- C `isspace`: space, HT, LF, VT, FF, CR. -/
def isSpace (b : UInt8) : Bool := b == 32 || (9 ≤ b && b ≤ 13)

/-- Lowercase hexadecimal digit for a value below 16. -/
def hexDigit (n : UInt8) : UInt8 := if n < 10 then 48 + n else 87 + n

/-- `lowercase`: ASCII `A`–`Z` to `a`–`z`, other bytes unchanged. -/
def lowercase (b : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity b.size
  for x in b do
    out := out.push (if 65 ≤ x && x ≤ 90 then x + 32 else x)
  return out

#guard (lowercase ⟨#[0x54, 0x65, 0x00, 0x43, 0xC4]⟩).data == #[0x74, 0x65, 0x00, 0x63, 0xC4]
#guard (lowercase ⟨#[]⟩).data == #[]

/-- `hexEncode`: each byte as two lowercase hexadecimal digits. -/
def hexEncode (b : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity (2 * b.size)
  for x in b do
    out := (out.push (hexDigit (x / 16))).push (hexDigit (x % 16))
  return out

#guard (hexEncode ⟨#[0x54, 0x00, 0xFF]⟩).data == #[0x35, 0x34, 0x30, 0x30, 0x66, 0x66]
#guard (hexEncode ⟨#[]⟩).data == #[]

end SecLang
```

Write the guards first with the two `def`s commented out, run `cd formal && lake build`, expect `unknown identifier 'SecLang.lowercase'`; then uncomment.

- [ ] **Step 3: Build** — `cd formal && lake build` → `Build completed successfully`. A failing `#guard` reports `error: ... evaluates to false`.
- [ ] **Step 4: Validate** — `uv run python tools/validate.py` → `0 error(s)` (unchanged scope).
- [ ] **Step 5: Commit** — `git add formal && git commit -m "feat(formal): Lake project with lowercase and hexEncode"` + attribution lines.

---

### Task 2: `urlDecodeUni`

**Files:**
- Modify: `formal/SecLang/Transformations.lean` (append before `end SecLang`)

**Interfaces:**
- Consumes: `byteAt`, `hexAt`.
- Produces: `SecLang.urlDecodeUniWith : (Nat → Option UInt8) → ByteArray → ByteArray`, `SecLang.urlDecodeUni : ByteArray → ByteArray`.

- [ ] **Step 1: Failing guards**

```lean
#guard (urlDecodeUni ⟨"Test+Case".toUTF8.data⟩).data == "Test Case".toUTF8.data
#guard (urlDecodeUni ⟨"%41%ff%u0042".toUTF8.data⟩).data == #[0x41, 0xFF, 0x42]
#guard (urlDecodeUni ⟨"%uff01%uff5e%uff00%uff7f".toUTF8.data⟩).data == #[0x21, 0x7E, 0x00, 0x7F]
#guard (urlDecodeUni ⟨"%u1141".toUTF8.data⟩).data == #[0x41]
#guard (urlDecodeUni ⟨"%u00%u0020".toUTF8.data⟩).data == "%u00 ".toUTF8.data
#guard (urlDecodeUni ⟨"%0g%20%%%".toUTF8.data⟩).data == "%0g %%%".toUTF8.data
#guard (urlDecodeUniWith (fun c => if c == 0x1141 then some 0x5A else none) ⟨"%u1141".toUTF8.data⟩).data == #[0x5A]
```

Run `lake build` → unknown identifier.

- [ ] **Step 2: Implement** (insert above the guards)

```lean
/-- The byte for a `%uXXXX` escape: the mapping table when it has an entry, otherwise the
low byte, folded from full-width ASCII (`FF01`–`FF5E`) to ASCII.
Source: `msc_util.c` `urldecode_uni_nonstrict_inplace_ex`. -/
def uniByte (map : Nat → Option UInt8) (h2 h3 h4 h5 : UInt8) : UInt8 :=
  match map (h2.toNat * 4096 + h3.toNat * 256 + h4.toNat * 16 + h5.toNat) with
  | some m => m
  | none =>
    let low := h4 * 16 + h5
    if h2 == 15 && h3 == 15 && 0 < low && low < 0x5F then low + 0x20 else low

/-- `urlDecodeUni` with a `SecUnicodeMapFile` table (`map code = none` for no entry). -/
def urlDecodeUniWith (map : Nat → Option UInt8) (b : ByteArray) : ByteArray :=
  go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let c := b[i]
      if c == '+'.toUInt8 then go (i + 1) (out.push ' '.toUInt8)
      else if c != '%'.toUInt8 then go (i + 1) (out.push c)
      else
        let u := byteAt b (i + 1)
        if u == some 'u'.toUInt8 || u == some 'U'.toUInt8 then
          match hexAt b (i + 2), hexAt b (i + 3), hexAt b (i + 4), hexAt b (i + 5) with
          | some h2, some h3, some h4, some h5 => go (i + 6) (out.push (uniByte map h2 h3 h4 h5))
          | _, _, _, _ => go (i + 2) ((out.push c).push (u.getD 0))   -- "%u" kept verbatim
        else
          match hexAt b (i + 1), hexAt b (i + 2) with
          | some h1, some h2 => go (i + 3) (out.push (h1 * 16 + h2))
          | _, _ => go (i + 1) (out.push c)                           -- "%" kept verbatim
    else out
  termination_by b.size - i

/-- `urlDecodeUni` without a mapping table (the engines' default). -/
def urlDecodeUni : ByteArray → ByteArray := urlDecodeUniWith fun _ => none
```

- [ ] **Step 3: Build** — `lake build` → success. If `termination_by` fails, add `decreasing_by all_goals simp_wf; omega` (still no proof content beyond arithmetic).
- [ ] **Step 4: Commit** — `feat(formal): urlDecodeUni`.

---

### Task 3: `cssDecode` and the spec paragraph it corrects

**Files:**
- Modify: `formal/SecLang/Transformations.lean`
- Modify: `spec/07-transformations.md` (`### cssDecode`, the `**Semantics.**` paragraph)

**Interfaces:**
- Produces: `SecLang.cssDecode : ByteArray → ByteArray`.

- [ ] **Step 1: Failing guards**

```lean
#guard (cssDecode ⟨"\\a\\b\\n\\?\\12\\123\\1234\\ff01\\ff5e".toUTF8.data⟩).data
  == #[0x0A, 0x0B, 0x6E, 0x3F, 0x12, 0x23, 0x34, 0x21, 0x7E]
#guard (cssDecode ⟨"\\1A\\1 A\\1234567\\123456 7\\1x\\1 x".toUTF8.data⟩).data
  == #[0x1A, 0x01, 0x41, 0x56, 0x37, 0x56, 0x37, 0x01, 0x78, 0x01, 0x78]
#guard (cssDecode ⟨"\\\n\\\u{0}  s\\".toUTF8.data⟩).data == #[0x00, 0x20, 0x20, 0x73]
#guard (cssDecode ⟨"\\  x".toUTF8.data⟩).data == #[0x20, 0x20, 0x78]
#guard (cssDecode ⟨"\\0ff21\\00ff21\\1ff21".toUTF8.data⟩).data == #[0x41, 0x41, 0x21]
```

(`\0ff21`: five digits with a leading zero fold; `\1ff21` does not.)

- [ ] **Step 2: Implement**

```lean
/-- Number of hexadecimal digits at `p`, at most `max`. -/
def hexRun (b : ByteArray) (p : Nat) : Nat → Nat
  | 0 => 0
  | k + 1 => if (hexAt b p).isSome then 1 + hexRun b (p + 1) k else 0

/-- The byte for a CSS escape of `j` (1–6) hexadecimal digits starting at `p`: the last two
digits, folded from full-width ASCII when the escape is `ffXX`, `0ffXX` or `00ffXX`.
Source: `msc_util.c` `css_decode_inplace`. -/
def cssByte (b : ByteArray) (p j : Nat) : UInt8 :=
  let d := fun k => (hexAt b (p + k)).getD 0
  if j == 1 then d 0
  else
    let low := d (j - 2) * 16 + d (j - 1)
    let fullWidth := j == 4 || (j == 5 && d 0 == 0) || (j == 6 && d 0 == 0 && d 1 == 0)
    if fullWidth && d (j - 3) == 15 && d (j - 4) == 15 && 0 < low && low < 0x5F then low + 0x20
    else low

/-- `cssDecode`: CSS 2.x escapes. -/
def cssDecode (b : ByteArray) : ByteArray := go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let c := b[i]
      if c != '\\'.toUInt8 then go (i + 1) (out.push c)
      else match byteAt b (i + 1) with
        | none => out                                    -- trailing backslash: dropped
        | some n =>
          let j := hexRun b (i + 1) 6
          if j == 0 then
            if n == '\n'.toUInt8 then go (i + 2) out     -- escaped newline: dropped
            else go (i + 2) (out.push n)                 -- escaped byte: itself
          else
            let ws := if (byteAt b (i + 1 + j)).any isSpace then 1 else 0
            go (i + 1 + j + ws) (out.push (cssByte b (i + 1) j))
    else out
  termination_by b.size - i
```

- [ ] **Step 3: Build** — `lake build` → success.
- [ ] **Step 4: Spec fix** — replace the `**Semantics.**` paragraph of `### cssDecode` in `spec/07-transformations.md` with:

```markdown
**Semantics.** Decodes CSS 2.x escape sequences. A backslash followed by one to six
hexadecimal digits yields one byte: the value of the last two digits (of the single digit
for a one-digit escape), except that a full-width ASCII escape, `\ffXX`, `\0ffXX` or
`\00ffXX` with `XX` in `01`–`5e`, yields `XX + 0x20`, its ASCII counterpart. One
whitespace byte (space, HT, LF, VT, FF or CR) directly after the digits is consumed. A
backslash followed by a newline is removed, a backslash followed by any other byte
yields that byte, and a trailing backslash is removed.
```

Run `uv run python tools/validate.py` → `0 error(s)`.

- [ ] **Step 5: Commit** — `feat(formal): cssDecode; spec: cssDecode states the low-byte and full-width rule`.

---

### Task 4: `base64Decode`

**Files:**
- Modify: `formal/SecLang/Transformations.lean`

**Interfaces:**
- Produces: `SecLang.base64Decode : ByteArray → ByteArray`.

- [ ] **Step 1: Failing guards**

```lean
#guard (base64Decode ⟨"VGVzdENhc2U=".toUTF8.data⟩).data == "TestCase".toUTF8.data
#guard (base64Decode ⟨"VGVzdENhc2Ux".toUTF8.data⟩).data == "TestCase1".toUTF8.data
#guard (base64Decode ⟨"VGVzdABDYXNl".toUTF8.data⟩).data == #[0x54, 0x65, 0x73, 0x74, 0x00, 0x43, 0x61, 0x73, 0x65]
#guard (base64Decode ⟨"VGVzdENhc2U".toUTF8.data⟩).data == "TestCase".toUTF8.data
#guard (base64Decode ⟨"VGVzdENhc2UxV".toUTF8.data⟩).data == "TestCase1".toUTF8.data
#guard (base64Decode ⟨"VGVz*dENh".toUTF8.data⟩).data == "Tes".toUTF8.data
#guard (base64Decode ⟨#[0x56, 0x47, 0x56, 0x7A, 0x00, 0x64]⟩).data == "Tes".toUTF8.data
#guard (base64Decode ⟨#[]⟩).data == #[]
```

- [ ] **Step 2: Implement**

```lean
/-- Value of a standard Base64 alphabet byte (RFC 4648 §4). -/
def b64Val (b : UInt8) : Option UInt8 :=
  if 65 ≤ b && b ≤ 90 then some (b - 65)        -- A-Z
  else if 97 ≤ b && b ≤ 122 then some (b - 71)  -- a-z
  else if 48 ≤ b && b ≤ 57 then some (b + 4)    -- 0-9
  else if b == '+'.toUInt8 then some 62
  else if b == '/'.toUInt8 then some 63
  else none

/-- Sextets of the longest alphabet-only prefix. Decoding stops at the first other byte:
padding, NUL (`spec/07#base64decode`), or anything else (the ModSecurity v2 / Coraza
reading of input the spec leaves unspecified; libmodsecurity rejects such input). -/
def b64Sextets (b : ByteArray) : Array UInt8 := Id.run do
  let mut out := #[]
  for x in b do
    match b64Val x with
    | some v => out := out.push v
    | none => return out
  return out

/-- `base64Decode`: full quanta give three bytes; a trailing two or three sextets give one
or two; a trailing single sextet gives nothing. -/
def base64Decode (b : ByteArray) : ByteArray := Id.run do
  let s := b64Sextets b
  let mut out := ByteArray.emptyWithCapacity (s.size / 4 * 3 + 2)
  let mut i := 0
  while i + 4 ≤ s.size do
    out := out.push (s[i]! <<< 2 ||| s[i + 1]! >>> 4)
    out := out.push (s[i + 1]! <<< 4 ||| s[i + 2]! >>> 2)
    out := out.push (s[i + 2]! <<< 6 ||| s[i + 3]!)
    i := i + 4
  if i + 2 ≤ s.size then out := out.push (s[i]! <<< 2 ||| s[i + 1]! >>> 4)
  if i + 3 ≤ s.size then out := out.push (s[i + 1]! <<< 4 ||| s[i + 2]! >>> 2)
  return out
```

- [ ] **Step 3: Build** — `lake build` → success.
- [ ] **Step 4: Commit** — `feat(formal): base64Decode`.

---

### Task 5: Corpus runner, first real run, triage

**Files:**
- Modify: `formal/Main.lean` (replace the stub)
- Create: `formal/README.md`

**Interfaces:**
- Consumes: the five definitions.
- Produces: `lake exe seclang-check [dir]`, exit 0 iff every formalized case passes.

- [ ] **Step 1: Runner**

```lean
import Lean.Data.Json
import SecLang

/-!
Runs `tests/unit/transformations/*.json` against the Lean definitions. Per file: skipped
when its transformation is not formalized, otherwise `N passed, M failed` plus one line per
mismatch in the adapters' wording. Exit 1 when anything failed or could not be loaded.
-/
open Lean SecLang

/-- The transformations the model defines, by corpus name. -/
def formalized : List (String × (ByteArray → ByteArray)) :=
  [("lowercase", lowercase), ("hexEncode", hexEncode), ("urlDecodeUni", urlDecodeUni),
   ("cssDecode", cssDecode), ("base64Decode", base64Decode)]

/-- A unit-tier byte string (every code point ≤ U+00FF, one byte each; `tests/README.md`). -/
def toBytes (s : String) : Except String ByteArray := do
  let mut out := ByteArray.emptyWithCapacity s.length
  for c in s.toList do
    if c.toNat > 255 then throw s!"not a byte string: {s.quote}"
    out := out.push c.toNat.toUInt8
  return out

def ofBytes (b : ByteArray) : String :=
  String.mk (b.toList.map fun x => Char.ofNat x.toNat)

structure Case where
  name : String
  input : String
  output : String
  ret : Nat

def Case.ofJson (j : Json) : Except String Case := do
  return {
    name := ← j.getObjVal? "name" >>= Json.getStr?
    input := ← j.getObjVal? "input" >>= Json.getStr?
    output := ← j.getObjVal? "output" >>= Json.getStr?
    ret := ← j.getObjVal? "ret" >>= Json.getNat? }

/-- The mismatch for one case, if any. -/
def check (f : ByteArray → ByteArray) (c : Case) : Except String (Option String) := do
  let got := ofBytes (f (← toBytes c.input))
  if got != c.output then
    return some s!"t:{c.name} on {c.input.quote}: output {got.quote}, expected {c.output.quote}"
  if (got != c.input) != (c.ret == 1) then
    return some s!"t:{c.name} on {c.input.quote}: changed={got != c.input}, expected ret={c.ret}"
  return none

/-- Runs one corpus file; `true` when it passed or was skipped. -/
def runFile (path : System.FilePath) : IO Bool := do
  let name := path.fileName.getD path.toString
  let txt ← IO.FS.readFile path
  match Json.parse txt >>= Json.getArr? >>= (·.mapM Case.ofJson) with
  | .error e => IO.println s!"{name}: cannot load: {e}"; return false
  | .ok cases =>
    let some first := cases[0]? | IO.println s!"{name}: skipped (no cases)"; return true
    let some f := formalized.lookup first.name | IO.println s!"{name}: skipped (not formalized)"; return true
    let mut failed : Array String := #[]
    for c in cases do
      match check f c with
      | .ok none => pure ()
      | .ok (some m) => failed := failed.push m
      | .error e => failed := failed.push e
    IO.println s!"{name}: {cases.size - failed.size} passed, {failed.size} failed"
    for m in failed do IO.println s!"  {m}"
    return failed.isEmpty

def main (args : List String) : IO UInt32 := do
  let dir : System.FilePath := args.headD "../tests/unit/transformations"
  let files := (← dir.readDir).filter (·.path.extension == some "json")
    |>.qsort (·.fileName < ·.fileName)
  let mut ok := true
  for e in files do
    ok := (← runFile e.path) && ok
  return if ok then 0 else 1
```

- [ ] **Step 2: Negative check** — in the scratchpad, write `bad/lowercase.json` with one case expecting `"X"` → `"X"` with `ret: 1`, and `bad/hexEncode.json` with an input containing `Ā`. Run `cd formal && lake build && lake exe seclang-check <scratch>/bad; echo $?` → the first file prints `output "x", expected "X"`, the second prints `not a byte string`, exit `1`.
- [ ] **Step 3: First real run** — `cd formal && lake exe seclang-check | tee <scratch>/run1.txt; echo $?`. Expected shape: 5 files with counts, 30 `skipped (not formalized)`. **Triage every mismatch**: compare the Lean definition against the C and the spec; classify as spec/corpus defect (fix in `spec/` or the JSON plus `tools/import_sts.py` sets, note the file is `HAND_MAINTAINED` where applicable) or model defect (fix the Lean, add a `#guard`). Record each in the ledger. Rerun until `0` with 51 passing cases.
- [ ] **Step 4: README** — `formal/README.md`:

```markdown
# Formal model

Lean 4 definitions of the specification, executable against the conformance corpus.
Status: spike — five transformations (`SecLang/Transformations.lean`), see
`docs/superpowers/specs/2026-10-08-lean-spike-design.md`.

## Build and run

Install elan (`brew install elan-init` or <https://github.com/leanprover/elan>); the
toolchain in `lean-toolchain` is fetched on first build.

    cd formal
    lake build                 # also evaluates every #guard
    lake exe seclang-check     # ../tests/unit/transformations by default; exit 1 on any mismatch

## What a mismatch means

The model is a reference, not an engine: it has no rows in `compat/known-gaps.md`. A
mismatch is a defect in the corpus, the spec text or the model, classified as for an
adapter disagreement (`AGENTS.md`) and fixed before merge. Files for transformations
not yet formalized are reported as skipped.
```

- [ ] **Step 5: Validate and commit** — `uv run python tools/validate.py` → `0 error(s)`; `git add formal spec tests tools` as touched; `feat(formal): corpus runner` (plus separate `fix(spec)`/`fix(tests)` commits for any triage fixes, each naming the case).

---

### Task 6: CI, repository docs, site link rule

**Files:**
- Modify: `.github/workflows/validate.yml` (append job), `AGENTS.md` (layout table row + "Before you commit"), `README.md` (layout table row), `spec/07-transformations.md` (preamble sentence), `site/layouts/_partials/rewrite-refs.html:15-16` (add `formal` to the path alternation)

- [ ] **Step 1: CI job** — append to `validate.yml`:

```yaml
  lean:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: leanprover/lean-action@f061402b660e0c34644504b324e830f2991d4865 # v1.6.1
        with:
          lake-package-directory: formal
          auto-config: "false"
          build: "true"
      - run: lake exe seclang-check
        working-directory: formal
```

- [ ] **Step 2: AGENTS.md** — add after the `tools/` row:

```
| `formal/` | Lean 4 model (`lakefile.toml`, no dependencies). `SecLang/Transformations.lean` defines transformations over `ByteArray`; `lake exe seclang-check` runs `tests/unit/transformations` against them and exits non-zero on any mismatch. The model is a reference, not an engine: no known-gaps rows; a mismatch is a corpus, spec or model defect to fix. | `cd formal && lake build && lake exe seclang-check` (needs elan; `formal/README.md`) |
```

and to "Before you commit": `(cd formal && lake build && lake exe seclang-check)   # when formal/, spec/07 or tests/unit/transformations changed`.

- [ ] **Step 3: README.md** — a `formal/` row after `adapters/` in its layout table, one sentence.
- [ ] **Step 4: Spec preamble** — after the `tests/README.md` sentence in `spec/07-transformations.md` lines 9–11 add: "The Lean definitions in `formal/SecLang/Transformations.lean` are the executable reference for the transformations they cover (`formal/README.md`)." Then extend both `replaceRE` alternations in `site/layouts/_partials/rewrite-refs.html` from `(?:tests|adapters|tools)` to `(?:tests|adapters|tools|formal)`.
- [ ] **Step 5: Verify** — `uv run python tools/validate.py` → `0 error(s)`; `hugo -s site --gc --minify --cleanDestinationDir && site/smoke.sh` → passes; `grep -o 'blob/main/formal/[^"]*' site/public/spec/07-transformations/index.html` shows the two links.
- [ ] **Step 6: Commit** — `ci(formal): build and run the Lean model; docs: formal/ in AGENTS.md, README and the site link rule`.

---

### Task 7: Branch review and finish

- [ ] **Step 1: Ledger** — write the per-task ledger (what was built, every triage classification, deviations from this plan) into the final branch summary.
- [ ] **Step 2: Whole-branch review** — `superpowers:requesting-code-review` on `main..lean-spike` with the design doc as the reference; one fix pass.
- [ ] **Step 3: Finish** — `superpowers:finishing-a-development-branch`; the maintainer's standing choice is "merge to main locally", never push.
