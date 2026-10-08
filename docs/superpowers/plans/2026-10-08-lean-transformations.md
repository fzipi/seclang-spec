# Lean Stage 1: All Transformations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every transformation in `spec/07-transformations.md` has a Lean definition under `formal/`, `lake exe seclang-check` runs all 36 corpus files with no failure and no skip, and every prose/corpus/engine disagreement the definitions expose is fixed in the repository.

**Architecture:** Byte helpers move to `SecLang/Bytes.lean`; MD5 and SHA-1 live in `SecLang/Digest.lean`; `SecLang/Transformations.lean` holds the 35 definitions grouped Core then Extended, each with `#guard` checks taken from the corpus or the C source. `Main.lean`'s `formalized` table lists every name. Spec, corpus and known-gaps edits ride with the task whose definition forces them.

**Tech Stack:** Lean `v4.34.1` via elan (`export PATH="$HOME/.elan/bin:$PATH"`), Lake 5. Python through `uv` for the importer and validator. Go for the Coraza adapter.

**Spec:** `docs/superpowers/specs/2026-10-08-lean-transformations-design.md` (§3 is the authority for every finding). Reference C: `cd ~/Workspace/OWASP/modsecurity/modsecurity && git show v2/master:apache2/msc_util.c` and `…:apache2/re_tfns.c`.

## Global Constraints

- No new dependency; `formal/lean-toolchain` stays `leanprover/lean4:v4.34.1`.
- Definitions are `ByteArray → ByteArray`, explicit loops; `termination_by b.size - i` for lookahead recursion, `Id.run do` with `for`/`while` otherwise.
- Every definition's docstring names the C function it models and any deliberate deviation.
- Guards are written first and watched failing (`Unknown identifier`) before the definition is added.
- Every commit passes `cd formal && lake build && lake exe seclang-check` (all files registered so far pass; the rest skip) and `uv run python tools/validate.py` (0 errors). Commits that touch `tests/` or `compat/` also pass `cd adapters/coraza && go test ./... -count=1`.
- Spec edits keep anchors; only `**Semantics.**`/`**Divergence notes.**` paragraphs change.
- Commit messages end with the two attribution lines. Never push.

## Review Focus

1. `hexDecode` on an odd-length input of valid digits (`01234567890a0`). Expected: six bytes, the trailing `0` dropped; guard in Task 2.
2. `removeComments` on a comment closed at the very end (`/* x */`). Expected: one NUL byte, as every engine produces; guard in Task 4.
3. `normalisePath` on a relative path that climbs above its start (`dir/../../foo`). Expected: `../foo`; guard in Task 6.
4. `utf8toUnicode` on a truncated lead byte at end of input (`a\xC3`). Expected: both bytes unchanged; guard in Task 6.
5. `base64DecodeExt` with a NUL inside the data (`VGVz\x00dENh`). Expected: `Tes`, decoding stops at NUL; guard in Task 3.

---

### Task 1: Bytes.lean split; uppercase, nulls, whitespace removal, trim, length, parity

**Files:**
- Create: `formal/SecLang/Bytes.lean`
- Modify: `formal/SecLang/Transformations.lean` (helpers removed, `import SecLang.Bytes`, new definitions appended before `end SecLang`), `formal/SecLang.lean`, `formal/Main.lean` (`formalized`), `spec/07-transformations.md` (`parityEven7bit`, `parityOdd7bit` semantics)

**Interfaces:**
- Produces: `SecLang.byteAt`, `hexVal`, `hexAt`, `isSpace`, `hexDigit`, `isDigit`, `isAlnum`, `isOctal`, `isHex`, `pushHex : ByteArray → UInt8 → ByteArray`, `takeWhile : ByteArray → (UInt8 → Bool) → Nat → Nat → Nat` (fuel last), `mapBytes : (UInt8 → UInt8) → ByteArray → ByteArray`, `filterBytes : (UInt8 → Bool) → ByteArray → ByteArray`; transformations `uppercase`, `removeNulls`, `replaceNulls`, `removeWhitespace`, `trimLeft`, `trimRight`, `trim`, `length`, `parityEven7bit`, `parityOdd7bit`, `parityZero7bit`.

- [ ] **Step 1: Bytes.lean** — move `byteAt`, `hexVal`, `hexAt`, `isSpace`, `hexDigit` out of `Transformations.lean` into:

```lean
/-! Byte-level helpers shared by the definitions. -/
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

def isHex (b : UInt8) : Bool := (hexVal b).isSome

/-- The hexadecimal digit at `i`, when there is one. -/
def hexAt (b : ByteArray) (i : Nat) : Option UInt8 := byteAt b i >>= hexVal

/-- C `isspace`: space, HT, LF, VT, FF, CR. -/
def isSpace (b : UInt8) : Bool := b == 32 || (9 ≤ b && b ≤ 13)

def isDigit (b : UInt8) : Bool := 48 ≤ b && b ≤ 57
def isOctal (b : UInt8) : Bool := 48 ≤ b && b ≤ 55
def isAlnum (b : UInt8) : Bool := isDigit b || (65 ≤ b && b ≤ 90) || (97 ≤ b && b ≤ 122)

/-- Lowercase hexadecimal digit for a value below 16. -/
def hexDigit (n : UInt8) : UInt8 := if n < 10 then 48 + n else 87 + n

/-- Appends the two lowercase hexadecimal digits of `x`. -/
def pushHex (out : ByteArray) (x : UInt8) : ByteArray :=
  (out.push (hexDigit (x / 16))).push (hexDigit (x % 16))

/-- Number of consecutive bytes satisfying `p` from `i`, at most `fuel`. -/
def takeWhile (b : ByteArray) (p : UInt8 → Bool) (i : Nat) : Nat → Nat
  | 0 => 0
  | k + 1 => if (byteAt b i).any p then 1 + takeWhile b p (i + 1) k else 0

def mapBytes (f : UInt8 → UInt8) (b : ByteArray) : ByteArray := ⟨b.data.map f⟩
def filterBytes (p : UInt8 → Bool) (b : ByteArray) : ByteArray := ⟨b.data.filter p⟩

end SecLang
```

`SecLang.lean` becomes `import SecLang.Bytes` + `import SecLang.Transformations`; `Transformations.lean` starts with `import SecLang.Bytes` and its `hexRun` becomes `takeWhile b isHex p` (replace the two call sites: `hexRun b (i + 1) 6` → `takeWhile b isHex (i + 1) 6`; delete `hexRun`). `lake build` must still pass (existing guards).

- [ ] **Step 2: Failing guards** (append before `end SecLang`):

```lean
#guard (uppercase ⟨"Test\u0000Case 1".toUTF8.data⟩).data == "TEST\u0000CASE 1".toUTF8.data
#guard (removeNulls ⟨#[0, 0x54, 0, 0, 0x43, 0]⟩).data == #[0x54, 0x43]
#guard (replaceNulls ⟨#[0, 0x54, 0]⟩).data == #[0x20, 0x54, 0x20]
#guard (removeWhitespace ⟨#[0x20, 0x54, 9, 10, 11, 12, 13, 0xA0, 0x43, 0]⟩).data == #[0x54, 0x43, 0]
#guard (trimLeft ⟨" \t  T \u0000 C \t\r\n ".toUTF8.data⟩).data == "T \u0000 C \t\r\n ".toUTF8.data
#guard (trimRight ⟨" \t  T \u0000 C \t\r\n ".toUTF8.data⟩).data == " \t  T \u0000 C".toUTF8.data
#guard (trim ⟨" \t  T \u0000 C \t\r\n ".toUTF8.data⟩).data == "T \u0000 C".toUTF8.data
#guard (trim ⟨"   ".toUTF8.data⟩).data == #[]
#guard (length ⟨"Test\u0000Case".toUTF8.data⟩).data == "9".toUTF8.data
#guard (length ⟨#[]⟩).data == "0".toUTF8.data
#guard (parityEven7bit ⟨"abc0".toUTF8.data⟩).data == #[0xE1, 0xE2, 0x63, 0x30]
#guard (parityOdd7bit ⟨"abc0".toUTF8.data⟩).data == #[0x61, 0x62, 0xE3, 0xB0]
#guard (parityZero7bit ⟨#[0xC2, 0x80, 0x00, 0xFF]⟩).data == #[0x42, 0x00, 0x00, 0x7F]
```

`lake build` → `Unknown identifier 'uppercase'`.

- [ ] **Step 3: Definitions** (insert above the guards):

```lean
/-- `uppercase`: ASCII `a`–`z` to `A`–`Z`. libmodsecurity `upper_case.cc`; absent from v2. -/
def uppercase : ByteArray → ByteArray := mapBytes fun x => if 97 ≤ x && x ≤ 122 then x - 32 else x

/-- `removeNulls`. re_tfns.c `msre_fn_removeNulls_execute`. -/
def removeNulls : ByteArray → ByteArray := filterBytes (· != 0)

/-- `replaceNulls`: NUL to space. re_tfns.c `msre_fn_replaceNulls_execute`. -/
def replaceNulls : ByteArray → ByteArray := mapBytes fun x => if x == 0 then 32 else x

/-- Whitespace for the whitespace transformations: C `isspace` or the NBSP byte `0xA0`. -/
def isWs (x : UInt8) : Bool := isSpace x || x == 0xA0

/-- `removeWhitespace`. re_tfns.c `msre_fn_removeWhitespace_execute`. -/
def removeWhitespace : ByteArray → ByteArray := filterBytes (!isWs ·)

/-- `trimLeft`: drop leading `isspace` bytes. re_tfns.c `msre_fn_trimLeft_execute`. -/
def trimLeft (b : ByteArray) : ByteArray :=
  let n := takeWhile b isSpace 0 b.size
  b.extract n b.size

/-- `trimRight`: drop trailing `isspace` bytes. re_tfns.c `msre_fn_trimRight_execute`. -/
def trimRight (b : ByteArray) : ByteArray := go b.size
where
  go : Nat → ByteArray
    | 0 => .empty
    | k + 1 => if (byteAt b k).any isSpace then go k else b.extract 0 (k + 1)

/-- `trim`. re_tfns.c `msre_fn_trim_execute`. -/
def trim (b : ByteArray) : ByteArray := trimRight (trimLeft b)

/-- `length`: the byte count as a decimal string. re_tfns.c `msre_fn_length_execute`. -/
def length (b : ByteArray) : ByteArray := (toString b.size).toUTF8

/-- `true` when `x` has an odd number of one bits (all eight). re_tfns.c
`msre_fn_parityEven7bit_execute`: `x ^= x >> 4; x &= 0xf; (0x6996 >> x) & 1`. -/
def oddParity (x : UInt8) : Bool :=
  let n := (x ^^^ (x >>> 4)) &&& 0xF
  ((0x6996 : UInt32) >>> n.toUInt32) &&& 1 == 1

/-- `parityEven7bit`: set bit 7 when the eight-bit parity is odd, clear it otherwise. A byte
whose bit 7 is already set therefore keeps odd parity (v2 and v3 behaviour, `spec/07`). -/
def parityEven7bit : ByteArray → ByteArray :=
  mapBytes fun x => if oddParity x then x ||| 0x80 else x &&& 0x7F

/-- `parityOdd7bit`: the complement rule of `parityEven7bit`. -/
def parityOdd7bit : ByteArray → ByteArray :=
  mapBytes fun x => if oddParity x then x &&& 0x7F else x ||| 0x80

/-- `parityZero7bit`: clear bit 7. re_tfns.c `msre_fn_parityZero7bit_execute`. -/
def parityZero7bit : ByteArray → ByteArray := mapBytes (· &&& 0x7F)
```

- [ ] **Step 4: Register and run** — add to `formalized` in `Main.lean`: `("uppercase", uppercase), ("removeNulls", removeNulls), ("replaceNulls", replaceNulls), ("removeWhitespace", removeWhitespace), ("trimLeft", trimLeft), ("trimRight", trimRight), ("trim", trim), ("length", length), ("parityEven7bit", parityEven7bit), ("parityOdd7bit", parityOdd7bit), ("parityZero7bit", parityZero7bit)`. `cd formal && lake build && lake exe seclang-check | grep -v skipped` → 16 files with `0 failed`.
- [ ] **Step 5: Spec** — in `spec/07-transformations.md` replace the `parityEven7bit` semantics line with: `**Semantics.** Sets bit 7 when the byte's eight-bit parity is odd and clears it otherwise, so a byte whose bit 7 is already set keeps odd parity (ModSecurity v2 `re_tfns.c`, libmodsecurity v3 `parity_even_7bit.h`).` and `parityOdd7bit` with: `**Semantics.** Clears bit 7 when the byte's eight-bit parity is odd and sets it otherwise; the mirror of `parityEven7bit`, with the same high-bit caveat.` `uv run python tools/validate.py` → 0 errors.
- [ ] **Step 6: Commit** — `feat(formal): byte helpers module; uppercase, nulls, whitespace, trim, length, parity`.

---

### Task 2: compressWhitespace, hexDecode, urlDecode, urlEncode, sqlHexDecode (+ corpus and known-gaps)

**Files:**
- Modify: `formal/SecLang/Transformations.lean`, `formal/Main.lean`, `spec/07-transformations.md` (`compressWhitespace`, `hexDecode`, `sqlHexDecode`), `tools/import_sts.py`, `tools/test_import_sts.py`, `tests/unit/transformations/hexDecode.json` (regenerated), `compat/known-gaps.md`
- Create: `tests/unit/transformations/compressWhitespace-extra.json`

- [ ] **Step 1: Failing guards**

```lean
#guard (compressWhitespace ⟨"  T  \t   C  ".toUTF8.data⟩).data == " T C ".toUTF8.data
#guard (compressWhitespace ⟨#[0x61, 0xA0, 0xA0, 0x62, 0x00]⟩).data == #[0x61, 0x20, 0x62, 0x00]
#guard (hexDecode ⟨"546573740043617365".toUTF8.data⟩).data == "Test\u0000Case".toUTF8.data
#guard (hexDecode ⟨"01234567890a0".toUTF8.data⟩).data == #[0x01, 0x23, 0x45, 0x67, 0x89, 0x0A]
#guard (urlDecode ⟨"Test+Case%41%u0042%".toUTF8.data⟩).data == "Test CaseA%u0042%".toUTF8.data
#guard (urlEncode ⟨" !*09AZaz~\u00ff".toUTF8.data⟩).data == "+%21*09AZaz%7e%c3%bf".toUTF8.data
#guard (sqlHexDecode ⟨"0x414243".toUTF8.data⟩).data == "ABC".toUTF8.data
#guard (sqlHexDecode ⟨"a0X41420x0xzz0x4".toUTF8.data⟩).data == "aAB0x0xzz0x4".toUTF8.data
```

(The `urlEncode` input `\u00ff` is two UTF-8 bytes `C3 BF` here, hence `%c3%bf`.) `lake build` → unknown identifier.

- [ ] **Step 2: Definitions**

```lean
/-- `compressWhitespace`: each run of whitespace (`isspace` or `0xA0`) becomes one space.
re_tfns.c `msre_fn_compressWhitespace_execute`. -/
def compressWhitespace (b : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity b.size
  let mut inWs := false
  for x in b do
    if isWs x then
      inWs := true
    else
      if inWs then out := out.push 32
      inWs := false
      out := out.push x
  if inWs then out := out.push 32
  return out

/-- `hexDecode`: every complete pair of bytes as two hexadecimal digits; a trailing odd byte
is dropped. A non-hex byte is unspecified (`spec/07#hexdecode`; v2 `hex2bytes_inplace` and
v3 `hex_decode.cc` apply digit arithmetic to it) and counts as 0 here. -/
def hexDecode (b : ByteArray) : ByteArray := go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if i + 1 < b.size then
      go (i + 2) (out.push ((hexAt b i).getD 0 * 16 + (hexAt b (i + 1)).getD 0))
    else out
  termination_by b.size - i

/-- `urlDecode`: `%XX` and `+`; no `%u`. msc_util.c `urldecode_nonstrict_inplace_ex`. -/
def urlDecode (b : ByteArray) : ByteArray := go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let c := b[i]
      if c == '+'.toUInt8 then go (i + 1) (out.push 32)
      else if c == '%'.toUInt8 then
        match hexAt b (i + 1), hexAt b (i + 2) with
        | some h1, some h2 => go (i + 3) (out.push (h1 * 16 + h2))
        | _, _ => go (i + 1) (out.push c)
      else go (i + 1) (out.push c)
    else out
  termination_by b.size - i

/-- `urlEncode`: space to `+`; `*`, digits and ASCII letters kept; every other byte `%xx`
in lowercase. msc_util.c `url_encode`. -/
def urlEncode (b : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity (3 * b.size)
  for x in b do
    if x == 32 then out := out.push '+'.toUInt8
    else if x == '*'.toUInt8 || isAlnum x then out := out.push x
    else out := pushHex (out.push '%'.toUInt8) x
  return out

/-- Number of consecutive hexadecimal digit pairs at `j`, at most `fuel`. -/
def hexPairs (b : ByteArray) (j : Nat) : Nat → Nat
  | 0 => 0
  | k + 1 => if isHex' j && isHex' (j + 1) then 1 + hexPairs b (j + 2) k else 0
where isHex' (p : Nat) : Bool := (hexAt b p).isSome

/-- `sqlHexDecode`: `0x` or `0X` followed by at least one pair of hexadecimal digits
becomes the bytes of every following pair; a `0x` with no pair is kept. msc_util.c
`sql_hex2bytes_inplace` (which, as a C-string loop, also stops at a NUL byte; v3
`sql_hex_decode.cc` and this definition process every byte). -/
def sqlHexDecode (b : ByteArray) : ByteArray := go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let isX := (byteAt b (i + 1)).any fun u => u == 'x'.toUInt8 || u == 'X'.toUInt8
      let n := if b[i] == '0'.toUInt8 && isX then hexPairs b (i + 2) b.size else 0
      if n == 0 then go (i + 1) (out.push b[i])
      else
        go (i + 2 + 2 * n) (Id.run do
          let mut o := out
          for k in [:n] do
            o := o.push ((hexAt b (i + 2 + 2 * k)).getD 0 * 16 + (hexAt b (i + 3 + 2 * k)).getD 0)
          return o)
    else out
  termination_by b.size - i
```

`lake build` → success (if `termination_by` for `sqlHexDecode.go` fails on the `n` branch, add `decreasing_by all_goals simp_wf; omega`).

- [ ] **Step 3: Corpus** — in `tools/import_sts.py` extend the exclusion key: `EXCLUDED_CASES` entries are `(name, param)`; add

```python
# Transformation cases (no param) the spec leaves unspecified, keyed by input
# (07-transformations.md#hexdecode: a non-hex byte is unspecified; v2/v3 emit digit-arithmetic garbage).
EXCLUDED_INPUTS = {
    ("hexDecode", "01234567890a0z01234567890a"),
    ("hexDecode", "01234567890az"),
}
```

and in `convert_case` change the first line to `if "resource" in case or (case.get("name"), case.get("param")) in EXCLUDED_CASES or (case.get("name"), case.get("input")) in EXCLUDED_INPUTS:`. Test first in `tools/test_import_sts.py` (`ConvertTests`):

```python
    def test_excluded_inputs_are_dropped(self):
        self.assertIsNone(import_sts.convert_case({"type": "tfn", "name": "hexDecode", "input": "01234567890az", "output": "x", "ret": 1}, "a#b"))
        self.assertIsNotNone(import_sts.convert_case({"type": "tfn", "name": "hexDecode", "input": "4142", "output": "AB", "ret": 1}, "a#b"))
```

RED (`AttributeError: EXCLUDED_INPUTS`/case not dropped) → implement → `uv run python -m unittest tools.test_import_sts` OK. Regenerate: `uv run python tools/import_sts.py ~/Workspace/OWASP/modsecurity/modsecurity/test/test-cases/secrules-language-tests --dest <scratch>/regen` and copy only `<scratch>/regen/transformations/hexDecode.json` over `tests/unit/transformations/hexDecode.json` (`git diff` shows exactly two cases removed).

Create `tests/unit/transformations/compressWhitespace-extra.json`:

```json
[
 {
  "type": "tfn",
  "name": "compressWhitespace",
  "input": "a\u00a0\u00a0b",
  "output": "a b",
  "ret": 1,
  "spec": "07-transformations.md#compresswhitespace",
  "note": "byte 0xA0 is whitespace, as in removeWhitespace (ModSecurity v2 NBSP, Coraza rawNBSP)"
 }
]
```

- [ ] **Step 4: Known gaps** — in `compat/known-gaps.md` change the hexDecode row to `| \`tests/unit/transformations/hexDecode.json\` | Coraza | an input with an odd length is returned unchanged instead of decoding the complete pairs (one case) | \`07-transformations.md#hexdecode\` |` and add after it: `| \`tests/unit/transformations/compressWhitespace-extra.json\` | libmodsecurity v3 | byte 0xA0 is not whitespace (\`isspace\` only, \`src/actions/transformations/compress_whitespace.cc\`); v2 and Coraza compress it | \`07-transformations.md#compresswhitespace\` |`.
- [ ] **Step 5: Spec** — `compressWhitespace`: `**Semantics.** Replaces every run of one or more whitespace bytes (space, tab, LF, VT, FF, CR, and the non-breaking space byte 0xA0, as in \`removeWhitespace\`) with a single space; NUL is not whitespace.` and `**Divergence notes.** libmodsecurity v3 (\`compress_whitespace.cc\`, \`isspace\`) does not treat 0xA0 as whitespace; ModSecurity v2 (\`NBSP\`) and Coraza (\`rawNBSP\`) do (\`compat/known-gaps.md\`).` `hexDecode`: `**Semantics.** Decodes every complete pair of bytes as two hexadecimal digits; a trailing odd byte is dropped. The result for a pair containing a byte that is not a hexadecimal digit is not specified (ModSecurity v2 \`hex2bytes_inplace\` and v3 \`hex_decode.cc\` apply their digit arithmetic to it; the corpus cases exercising this are excluded on import). Coraza 3.8.1 returns the input unchanged on an odd length (\`compat/known-gaps.md\`).` `sqlHexDecode`: `**Semantics.** Decodes SQL \`0xHH...\` hexadecimal literals (\`0x\` or \`0X\` followed by at least one pair of hexadecimal digits) to their bytes; a \`0x\` with no complete pair is kept as is.`
- [ ] **Step 6: Register, run, verify** — `formalized` gains `compressWhitespace`, `hexDecode`, `urlDecode`, `urlEncode`, `sqlHexDecode`. `lake build && lake exe seclang-check | grep -v skipped` → 22 files, 0 failed. `uv run python tools/validate.py` → 0 errors. `uv run python -m unittest discover -s tools -t .` OK. `cd adapters/coraza && go test ./... -count=1` → ok (hexDecode row still has its one failing case; the extra file passes on Coraza).
- [ ] **Step 7: Commit** — `feat(formal): compressWhitespace, hexDecode, urlDecode, urlEncode, sqlHexDecode; spec/tests: 0xA0 is whitespace, non-hex pairs unspecified`.

---

### Task 3: Base64 encode/decodeExt; MD5 and SHA-1

**Files:**
- Create: `formal/SecLang/Digest.lean`
- Modify: `formal/SecLang/Transformations.lean` (refactor `base64Decode` to share `b64Emit`), `formal/SecLang.lean`, `formal/Main.lean`, `spec/07-transformations.md` (`base64DecodeExt`)

- [ ] **Step 1: Failing guards** (Transformations.lean):

```lean
#guard (base64Encode ⟨"Test\u0000Case".toUTF8.data⟩).data == "VGVzdABDYXNl".toUTF8.data
#guard (base64Encode ⟨"TestCase1".toUTF8.data⟩).data == "VGVzdENhc2Ux".toUTF8.data
#guard (base64Encode ⟨"TestCase12".toUTF8.data⟩).data == "VGVzdENhc2UxMg==".toUTF8.data
#guard (base64Encode ⟨#[]⟩).data == #[]
#guard (base64DecodeExt ⟨"P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==".toUTF8.data⟩).data == "<script>alert(1)</script>".toUTF8.data
#guard (base64DecodeExt ⟨"VGVz\u0000dENh".toUTF8.data⟩).data == "Tes".toUTF8.data
#guard (base64DecodeExt ⟨"VG=Vz".toUTF8.data⟩).data == "Tes".toUTF8.data
```

Digest.lean guards (file created with the guards and the definitions commented out first):

```lean
#guard (hexEncode (md5 ⟨#[]⟩)).data == "d41d8cd98f00b204e9800998ecf8427e".toUTF8.data
#guard (hexEncode (md5 ⟨"TestCase".toUTF8.data⟩)).data == "c9aba2c3e60126169e80e9a26ba273c1".toUTF8.data
#guard (hexEncode (md5 ⟨(List.replicate 64 0x61).toArray⟩)).data == "014842d480b571495a4a0363793f7367".toUTF8.data
#guard (hexEncode (sha1 ⟨#[]⟩)).data == "da39a3ee5e6b4b0d3255bfef95601890afd80709".toUTF8.data
#guard (hexEncode (sha1 ⟨"TestCase".toUTF8.data⟩)).data == "a70ce38389e318bd2be18a0111c6dc76bd2cd9ed".toUTF8.data
#guard (hexEncode (sha1 ⟨(List.replicate 64 0x61).toArray⟩)).data == "0098ba824b5c16427bd7a1122a5a442a25ec644d".toUTF8.data
```

(`Digest.lean` imports `SecLang.Transformations` for `hexEncode`; `SecLang.lean` imports `SecLang.Digest`; `Main.lean` opens it.) `lake build` → unknown identifiers.

- [ ] **Step 2: Transformations.lean** — refactor and add:

```lean
/-- Bytes of a sextet sequence: full quanta give three bytes; a trailing two or three
sextets give one or two; a trailing single sextet gives nothing (`apr_base64_decode`). -/
def b64Emit (s : Array UInt8) : ByteArray := Id.run do
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

def base64Decode (b : ByteArray) : ByteArray := b64Emit (b64Sextets b)   -- replaces the inline body

/-- Sextets of every alphabet byte up to the first NUL; `=` and any other byte are skipped.
msc_util.c `decode_base64_ext` (its "`=` after a dangling sextet yields the empty value"
quirk is not modelled: `spec/07#base64decodeext` leaves it unspecified). -/
def b64SextetsExt (b : ByteArray) : Array UInt8 := Id.run do
  let mut out := #[]
  for x in b do
    if x == 0 then return out
    if let some v := b64Val x then out := out.push v
  return out

/-- `base64DecodeExt`. -/
def base64DecodeExt (b : ByteArray) : ByteArray := b64Emit (b64SextetsExt b)

/-- Alphabet byte of a sextet. -/
def b64Char (v : UInt8) : UInt8 :=
  if v < 26 then 65 + v else if v < 52 then 71 + v else if v < 62 then v - 4
  else if v == 62 then '+'.toUInt8 else '/'.toUInt8

/-- `base64Encode`: RFC 4648 §4 with `=` padding. re_tfns.c `msre_fn_base64Encode_execute`
(`apr_base64_encode`). -/
def base64Encode (b : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity ((b.size + 2) / 3 * 4)
  let mut i := 0
  while i + 3 ≤ b.size do
    let x := b[i]!; let y := b[i + 1]!; let z := b[i + 2]!
    out := out.push (b64Char (x >>> 2))
    out := out.push (b64Char (((x &&& 3) <<< 4) ||| (y >>> 4)))
    out := out.push (b64Char (((y &&& 15) <<< 2) ||| (z >>> 6)))
    out := out.push (b64Char (z &&& 63))
    i := i + 3
  if i + 1 == b.size then
    let x := b[i]!
    out := out.push (b64Char (x >>> 2))
    out := out.push (b64Char ((x &&& 3) <<< 4))
    out := (out.push 61).push 61
  else if i + 2 == b.size then
    let x := b[i]!; let y := b[i + 1]!
    out := out.push (b64Char (x >>> 2))
    out := out.push (b64Char (((x &&& 3) <<< 4) ||| (y >>> 4)))
    out := out.push (b64Char ((y &&& 15) <<< 2))
    out := out.push 61
  return out
```

- [ ] **Step 3: Digest.lean**

```lean
import SecLang.Transformations
/-! MD5 (RFC 1321) and SHA-1 (RFC 3174) over byte arrays, for `t:md5` and `t:sha1`. -/
namespace SecLang

def rotl (x n : UInt32) : UInt32 := (x <<< n) ||| (x >>> (32 - n))

/-- Message plus `0x80`, zero padding to 56 mod 64, and the bit length as eight bytes
(little-endian when `le`, else big-endian). -/
def padMessage (b : ByteArray) (le : Bool) : ByteArray := Id.run do
  let bits := b.size * 8
  let mut out := b.push 0x80
  while out.size % 64 != 56 do out := out.push 0
  for k in [:8] do
    let shift := if le then 8 * k else 8 * (7 - k)
    out := out.push ((bits >>> shift) % 256).toUInt8
  return out

def wordLE (b : ByteArray) (i : Nat) : UInt32 :=
  b[i]!.toUInt32 ||| (b[i + 1]!.toUInt32 <<< 8) ||| (b[i + 2]!.toUInt32 <<< 16) ||| (b[i + 3]!.toUInt32 <<< 24)

def wordBE (b : ByteArray) (i : Nat) : UInt32 :=
  (b[i]!.toUInt32 <<< 24) ||| (b[i + 1]!.toUInt32 <<< 16) ||| (b[i + 2]!.toUInt32 <<< 8) ||| b[i + 3]!.toUInt32

def pushLE (out : ByteArray) (w : UInt32) : ByteArray :=
  (((out.push w.toUInt8).push (w >>> 8).toUInt8).push (w >>> 16).toUInt8).push (w >>> 24).toUInt8

def pushBE (out : ByteArray) (w : UInt32) : ByteArray :=
  (((out.push (w >>> 24).toUInt8).push (w >>> 16).toUInt8).push (w >>> 8).toUInt8).push w.toUInt8

def md5S : Array UInt32 := #[7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21]

/-- `floor(abs(sin(i + 1)) * 2^32)`. -/
def md5K : Array UInt32 := #[
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

/-- `md5`: the 16-byte digest. re_tfns.c `msre_fn_md5_execute` (`apr_md5`). -/
def md5 (msg : ByteArray) : ByteArray := Id.run do
  let m := padMessage msg true
  let mut a0 : UInt32 := 0x67452301
  let mut b0 : UInt32 := 0xefcdab89
  let mut c0 : UInt32 := 0x98badcfe
  let mut d0 : UInt32 := 0x10325476
  for blk in [:m.size / 64] do
    let base := blk * 64
    let mut a := a0; let mut b := b0; let mut c := c0; let mut d := d0
    for i in [:64] do
      let (f, g) :=
        if i < 16 then ((b &&& c) ||| (~~~b &&& d), i)
        else if i < 32 then ((d &&& b) ||| (~~~d &&& c), (5 * i + 1) % 16)
        else if i < 48 then (b ^^^ c ^^^ d, (3 * i + 5) % 16)
        else (c ^^^ (b ||| ~~~d), (7 * i) % 16)
      let f := f + a + md5K[i]! + wordLE m (base + 4 * g)
      a := d; d := c; c := b
      b := b + rotl f md5S[(i / 16) * 4 + i % 4]!
    a0 := a0 + a; b0 := b0 + b; c0 := c0 + c; d0 := d0 + d
  return pushLE (pushLE (pushLE (pushLE .empty a0) b0) c0) d0

/-- `sha1`: the 20-byte digest. re_tfns.c `msre_fn_sha1_execute` (`apr_sha1`). -/
def sha1 (msg : ByteArray) : ByteArray := Id.run do
  let m := padMessage msg false
  let mut h0 : UInt32 := 0x67452301
  let mut h1 : UInt32 := 0xEFCDAB89
  let mut h2 : UInt32 := 0x98BADCFE
  let mut h3 : UInt32 := 0x10325476
  let mut h4 : UInt32 := 0xC3D2E1F0
  for blk in [:m.size / 64] do
    let base := blk * 64
    let mut w : Array UInt32 := Array.mkArray 80 0
    for t in [:16] do w := w.set! t (wordBE m (base + 4 * t))
    for t in [16:80] do w := w.set! t (rotl (w[t - 3]! ^^^ w[t - 8]! ^^^ w[t - 14]! ^^^ w[t - 16]!) 1)
    let mut a := h0; let mut b := h1; let mut c := h2; let mut d := h3; let mut e := h4
    for t in [:80] do
      let (f, k) : UInt32 × UInt32 :=
        if t < 20 then ((b &&& c) ||| (~~~b &&& d), 0x5A827999)
        else if t < 40 then (b ^^^ c ^^^ d, 0x6ED9EBA1)
        else if t < 60 then ((b &&& c) ||| (b &&& d) ||| (c &&& d), 0x8F1BBCDC)
        else (b ^^^ c ^^^ d, 0xCA62C1D6)
      let temp := rotl a 5 + f + e + k + w[t]!
      e := d; d := c; c := rotl b 30; b := a; a := temp
    h0 := h0 + a; h1 := h1 + b; h2 := h2 + c; h3 := h3 + d; h4 := h4 + e
  return pushBE (pushBE (pushBE (pushBE (pushBE .empty h0) h1) h2) h3) h4

end SecLang
```

(`Array.mkArray` may be `Array.replicate` on this toolchain; use whichever compiles.) `lake build` → success.

- [ ] **Step 4: Spec** — `base64DecodeExt`: `**Semantics.** Base64 decoding that ignores \`=\` and skips every other byte outside the alphabet instead of stopping at it; decoding stops at a NUL byte. The result when \`=\` follows a single dangling sextet is not specified (ModSecurity v2 \`decode_base64_ext\` returns the empty value).`
- [ ] **Step 5: Register, run** — `formalized` gains `base64Encode`, `base64DecodeExt`, `md5`, `sha1`. `lake exe seclang-check | grep -v skipped` → 26 files, 0 failed. Validator 0.
- [ ] **Step 6: Commit** — `feat(formal): base64Encode, base64DecodeExt, md5, sha1`.

---

### Task 4: cmdLine, removeCommentsChar, removeComments, replaceComments

**Files:**
- Modify: `formal/SecLang/Transformations.lean`, `formal/Main.lean`, `spec/07-transformations.md` (`cmdLine`, `removeCommentsChar`, `removeComments`)

- [ ] **Step 1: Failing guards**

```lean
#guard (cmdLine ⟨"C^OMMAND /C DIR".toUTF8.data⟩).data == "command/c dir".toUTF8.data
#guard (cmdLine ⟨"\"cmd\",;\t\r\n/c (x) \u000b".toUTF8.data⟩).data == "cmd/c (x) \u000b".toUTF8.data
#guard (removeCommentsChar ⟨"a/*b*/c--d#e<!--f-->g".toUTF8.data⟩).data == "abcdefg".toUTF8.data
#guard (removeComments ⟨"/* TestCase */".toUTF8.data⟩).data == #[0]
#guard (removeComments ⟨"Before/* T*/ /* e */ /* s */ /* t */\r\nCase ".toUTF8.data⟩).data == "Before   \r\nCase ".toUTF8.data
#guard (removeComments ⟨"a <!-- b --> c -- d".toUTF8.data⟩).data == "a  c ".toUTF8.data
#guard (removeComments ⟨"a # b".toUTF8.data⟩).data == "a ".toUTF8.data
#guard (removeComments ⟨"Before /* Test".toUTF8.data⟩).data == "Before  ".toUTF8.data
#guard (replaceComments ⟨"Before /* TestCase */ After".toUTF8.data⟩).data == "Before   After".toUTF8.data
#guard (replaceComments ⟨"Before/* Test".toUTF8.data⟩).data == "Before ".toUTF8.data
```

- [ ] **Step 2: Definitions**

```lean
/-- `cmdLine`. re_tfns.c `msre_fn_cmdline_execute`: deletes `"`, `'`, `\`, `^`; collapses
runs of space, `,`, `;`, HT, CR, LF to one space and drops that space before `/` or `(`;
lower-cases ASCII letters. v2 stops at a NUL byte (C string); v3 and Coraza, and this
definition, process every byte. -/
def cmdLine (b : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity b.size
  let mut space := false
  for x in b do
    if x == '"'.toUInt8 || x == '\''.toUInt8 || x == '\\'.toUInt8 || x == '^'.toUInt8 then
      continue
    if x == 32 || x == ','.toUInt8 || x == ';'.toUInt8 || x == 9 || x == 13 || x == 10 then
      if !space then
        out := out.push 32
        space := true
    else if x == '/'.toUInt8 || x == '('.toUInt8 then
      if space then out := out.extract 0 (out.size - 1)
      space := false
      out := out.push x
    else
      out := out.push (if 65 ≤ x && x ≤ 90 then x + 32 else x)
      space := false
  return out

/-- `removeCommentsChar`: drops `/*`, `*/`, `<!--`, `-->`, `--` and `#`. re_tfns.c
`msre_fn_removeCommentsChar_execute`. -/
def removeCommentsChar (b : ByteArray) : ByteArray := go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let c := b[i]
      let n1 := byteAt b (i + 1); let n2 := byteAt b (i + 2); let n3 := byteAt b (i + 3)
      if c == '/'.toUInt8 && n1 == some '*'.toUInt8 then go (i + 2) out
      else if c == '*'.toUInt8 && n1 == some '/'.toUInt8 then go (i + 2) out
      else if c == '<'.toUInt8 && n1 == some '!'.toUInt8 && n2 == some '-'.toUInt8 && n3 == some '-'.toUInt8 then go (i + 4) out
      else if c == '-'.toUInt8 && n1 == some '-'.toUInt8 && n2 == some '>'.toUInt8 then go (i + 3) out
      else if c == '-'.toUInt8 && n1 == some '-'.toUInt8 then go (i + 2) out
      else if c == '#'.toUInt8 then go (i + 1) out
      else go (i + 1) (out.push c)
    else out
  termination_by b.size - i

/-- `removeComments`. re_tfns.c `msre_fn_removeComments_execute`: outside a comment, `/*`
and `<!--` open one and `--` or `#` ends the value; inside, `*/` and `-->` close it and
the byte after the terminator is copied as is, which at end of input is the C terminator,
one NUL byte, in every engine (v3 `remove_comments.cc`; Coraza `remove_comments.go` pads
the input with NUL to reproduce it). An unterminated comment yields one space. -/
def removeComments (b : ByteArray) : ByteArray := go 0 false .empty
where
  go (i : Nat) (inComment : Bool) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let c := b[i]
      let n1 := byteAt b (i + 1); let n2 := byteAt b (i + 2); let n3 := byteAt b (i + 3)
      if !inComment then
        if c == '/'.toUInt8 && n1 == some '*'.toUInt8 then go (i + 2) true out
        else if c == '<'.toUInt8 && n1 == some '!'.toUInt8 && n2 == some '-'.toUInt8 && n3 == some '-'.toUInt8 then go (i + 4) true out
        else if (c == '-'.toUInt8 && n1 == some '-'.toUInt8) || c == '#'.toUInt8 then out
        else go (i + 1) false (out.push c)
      else
        if c == '*'.toUInt8 && n1 == some '/'.toUInt8 then go (i + 3) false (out.push (n2.getD 0))
        else if c == '-'.toUInt8 && n1 == some '-'.toUInt8 && n2 == some '>'.toUInt8 then go (i + 4) false (out.push (n3.getD 0))
        else go (i + 1) true out
    else if inComment then out.push 32 else out
  termination_by b.size - i

/-- `replaceComments`: each `/* ... */` becomes one space; an unterminated comment becomes
one space. re_tfns.c `msre_fn_replaceComments_execute`. -/
def replaceComments (b : ByteArray) : ByteArray := go 0 false .empty
where
  go (i : Nat) (inComment : Bool) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let c := b[i]
      let n1 := byteAt b (i + 1)
      if !inComment then
        if c == '/'.toUInt8 && n1 == some '*'.toUInt8 then go (i + 2) true out
        else go (i + 1) false (out.push c)
      else if c == '*'.toUInt8 && n1 == some '/'.toUInt8 then go (i + 2) false (out.push 32)
      else go (i + 1) true out
    else if inComment then out.push 32 else out
  termination_by b.size - i
```

- [ ] **Step 3: Spec** — `cmdLine`: `**Semantics.** Normalises a command line as the ModSecurity reference manual defines: deletes \`\\\`, \`"\`, \`'\`, \`^\`; replaces each run of the separators space, \`,\`, \`;\`, HT, CR and LF with one space and drops that space when \`/\` or \`(\` follows; lower-cases ASCII letters. VT and FF are ordinary bytes.` plus `**Divergence notes.** ModSecurity v2 (\`re_tfns.c\`) processes the value as a C string and stops at the first NUL byte; libmodsecurity v3 and Coraza process every byte.` `removeCommentsChar`: `**Semantics.** Removes the comment delimiters \`/*\`, \`*/\`, \`<!--\`, \`-->\`, \`--\` and \`#\` wherever they occur, leaving the text between them.` `removeComments`: `**Semantics.** Removes C-style \`/* ... */\` and HTML \`<!-- ... -->\` comments; a SQL \`--\` or shell \`#\` outside a comment ends the value there. The byte that follows a closing \`*/\` or \`-->\` is copied as is, which at the end of the value is the C string terminator: \`/* x */\` yields one NUL byte in every engine (ModSecurity v2 \`re_tfns.c\`, libmodsecurity v3 \`remove_comments.cc\`, Coraza \`remove_comments.go\`). An unterminated comment yields one space. CRS prefers \`removeCommentsChar\`.`
- [ ] **Step 4: Register, run** — `formalized` gains the four names. `lake exe seclang-check | grep -v skipped` → 30 files, 0 failed. Validator 0.
- [ ] **Step 5: Commit** — `feat(formal): cmdLine, removeCommentsChar, removeComments, replaceComments; spec: separator set, <!-- -->, terminator byte`.

---

### Task 5: escapeSeqDecode, jsDecode, htmlEntityDecode

**Files:**
- Modify: `formal/SecLang/Transformations.lean`, `formal/Main.lean`, `spec/07-transformations.md` (`jsDecode`)

- [ ] **Step 1: Failing guards**

```lean
#guard (escapeSeqDecode ⟨"\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\0\\12\\123".toUTF8.data⟩).data == #[7, 8, 12, 10, 13, 9, 11, 0x3F, 0x27, 0x22, 0, 10, 0x53]
#guard (escapeSeqDecode ⟨"\\8\\9\\666\\x41\\xag\\x\\".toUTF8.data⟩).data == "89\u00b6Axagx\\".toUTF8.data.filter (· != 0xC2)
#guard (jsDecode ⟨"\\u0041\\uff01\\x42\\101\\400\\a\\q\\".toUTF8.data⟩).data == "A!BA \u0007q\\".toUTF8.data
#guard (jsDecode ⟨"\\u\\u0\\u01\\u012".toUTF8.data⟩).data == "uu0u01u012".toUTF8.data
#guard (htmlEntityDecode ⟨"&#x41;&#X42&#67;&#68&quot;&AMP&lt&gt;&nbsp;&foo;&#xg;&#;&".toUTF8.data⟩).data
  == ("ABCD\"&<>".toUTF8.push 0xA0 ++ "&foo;&#xg;&#;&".toUTF8).data
```

(`\u00b6` is `C2 B6` in UTF-8; the filter drops the `C2` so the expected byte is `B6`, the low byte of octal 666.) `\400` in `jsDecode` decodes as two digits `\40` = space followed by `0`: expected `" 0"`? No: `\400`: three octal digits with first digit `4` > `3`, so v2 uses two digits → `\40` = 0x20 then literal `0`. The guard string above must therefore read `"A!BA 0\u0007q\\"`; use that.

- [ ] **Step 2: Definitions**

```lean
/-- The byte for a C/JavaScript single-letter escape; any other byte stands for itself. -/
def cEscape (n : UInt8) : UInt8 :=
  if n == 'a'.toUInt8 then 7 else if n == 'b'.toUInt8 then 8 else if n == 'f'.toUInt8 then 12
  else if n == 'n'.toUInt8 then 10 else if n == 'r'.toUInt8 then 13 else if n == 't'.toUInt8 then 9
  else if n == 'v'.toUInt8 then 11 else n

/-- Value of the `j` octal digits at `p`, modulo 256. -/
def octValue (b : ByteArray) (p j : Nat) : UInt8 := Id.run do
  let mut v : Nat := 0
  for k in [:j] do v := v * 8 + ((byteAt b (p + k)).getD 48 - 48).toNat
  return (v % 256).toUInt8

/-- `escapeSeqDecode`: ANSI C escapes. msc_util.c `ansi_c_sequences_decode_inplace`. -/
def escapeSeqDecode (b : ByteArray) : ByteArray := go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let c := b[i]
      if c != '\\'.toUInt8 then go (i + 1) (out.push c)
      else match byteAt b (i + 1) with
        | none => out.push c                                   -- lone trailing backslash kept
        | some n =>
          if n == 'x'.toUInt8 || n == 'X'.toUInt8 then
            match hexAt b (i + 2), hexAt b (i + 3) with
            | some h1, some h2 => go (i + 4) (out.push (h1 * 16 + h2))
            | _, _ => go (i + 2) (out.push n)                  -- "x" kept, backslash dropped
          else if isOctal n then
            let j := takeWhile b isOctal (i + 1) 3
            go (i + 1 + j) (out.push (octValue b (i + 1) j))
          else go (i + 2) (out.push (cEscape n))
    else out
  termination_by b.size - i

/-- `jsDecode`: `\uHHHH` (low byte, full-width fold as `urlDecodeUni`), `\xHH`, octal up to
three digits (two when three would exceed one byte), `\a \b \f \n \r \t \v`; any other
escaped byte stands for itself. msc_util.c `js_decode_nonstrict_inplace`. -/
def jsDecode (b : ByteArray) : ByteArray := go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let c := b[i]
      if c != '\\'.toUInt8 then go (i + 1) (out.push c)
      else match byteAt b (i + 1) with
        | none => out.push c
        | some n =>
          match n == 'u'.toUInt8, hexAt b (i + 2), hexAt b (i + 3), hexAt b (i + 4), hexAt b (i + 5) with
          | true, some h2, some h3, some h4, some h5 => go (i + 6) (out.push (uniByte (fun _ => none) h2 h3 h4 h5))
          | _, _, _, _, _ =>
            match n == 'x'.toUInt8, hexAt b (i + 2), hexAt b (i + 3) with
            | true, some h1, some h2 => go (i + 4) (out.push (h1 * 16 + h2))
            | _, _, _ =>
              if isOctal n then
                let j0 := takeWhile b isOctal (i + 1) 3
                let j := if j0 == 3 && n > '3'.toUInt8 then 2 else j0
                go (i + 1 + j) (out.push (octValue b (i + 1) j))
              else go (i + 2) (out.push (cEscape n))
    else out
  termination_by b.size - i

/-- The byte of a named entity, compared case-insensitively. -/
def namedEntity (name : ByteArray) : Option UInt8 :=
  let s := (lowercase name).data
  if s == "quot".toUTF8.data then some 0x22 else if s == "amp".toUTF8.data then some 0x26
  else if s == "lt".toUTF8.data then some 0x3C else if s == "gt".toUTF8.data then some 0x3E
  else if s == "nbsp".toUTF8.data then some 0xA0 else none

/-- Value of the `n` digits at `p` in the given base, modulo 256. -/
def digitsValue (b : ByteArray) (p n base : Nat) : UInt8 := Id.run do
  let mut v : Nat := 0
  for k in [:n] do v := v * base + ((byteAt b (p + k)).bind hexVal |>.getD 0).toNat
  return (v % 256).toUInt8

/-- `htmlEntityDecode`. msc_util.c `html_entities_decode_inplace`: `&#NNN;`, `&#xHH;` (the
`;` optional, the value modulo 256; v2's `strtol` saturates instead for values beyond
`long`) and the five named entities; anything else is copied. -/
def htmlEntityDecode (b : ByteArray) : ByteArray := go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      let c := b[i]
      if c != '&'.toUInt8 then go (i + 1) (out.push c)
      else if byteAt b (i + 1) == some '#'.toUInt8 then
        let hexForm := (byteAt b (i + 2)).any fun u => u == 'x'.toUInt8 || u == 'X'.toUInt8
        let start := if hexForm then i + 3 else i + 2
        let n := takeWhile b (if hexForm then isHex else isDigit) start b.size
        if n == 0 then go (i + 1) (out.push c)
        else
          let after := start + n
          let semi := if byteAt b after == some ';'.toUInt8 then 1 else 0
          go (after + semi) (out.push (digitsValue b start n (if hexForm then 16 else 10)))
      else
        let n := takeWhile b isAlnum (i + 1) b.size
        match if n == 0 then none else namedEntity (b.extract (i + 1) (i + 1 + n)) with
        | some v =>
          let after := i + 1 + n
          let semi := if byteAt b after == some ';'.toUInt8 then 1 else 0
          go (after + semi) (out.push v)
        | none => go (i + 1) (out.push c)
    else out
  termination_by b.size - i
```

- [ ] **Step 3: Spec** — `jsDecode`: `**Semantics.** Decodes JavaScript escapes: \`\\uHHHH\` (one byte, the low 8 bits of the code point; full-width forms \`\\uFF01\`–\`\\uFF5E\` map to their ASCII counterparts), \`\\xHH\`, octal \`\\ooo\` (up to three digits, two when three would exceed one byte), and \`\\a \\b \\f \\n \\r \\t \\v\`; a backslash before any other byte is removed.`
- [ ] **Step 4: Register, run** — `formalized` gains the three names. `lake exe seclang-check | grep -v skipped` → 33 files, 0 failed. Validator 0.
- [ ] **Step 5: Commit** — `feat(formal): escapeSeqDecode, jsDecode, htmlEntityDecode; spec: jsDecode decodes \a`.

---

### Task 6: normalisePath, normalisePathWin, utf8toUnicode

**Files:**
- Modify: `formal/SecLang/Transformations.lean`, `formal/Main.lean`, `spec/07-transformations.md` (`utf8toUnicode` divergence notes)

- [ ] **Step 1: Failing guards**

```lean
#guard (normalisePath ⟨"dir/../../foo".toUTF8.data⟩).data == "../foo".toUTF8.data
#guard (normalisePath ⟨"/dir/./subdir/../subsubdir/../subsubsubdir/../".toUTF8.data⟩).data == "/dir/".toUTF8.data
#guard (normalisePath ⟨"./..".toUTF8.data⟩).data == "..".toUTF8.data
#guard (normalisePath ⟨"/./.././../../../../../../../\u0000/../etc/./passwd".toUTF8.data⟩).data == "/etc/passwd".toUTF8.data
#guard (normalisePath ⟨"dir//.//..//.//..//..//foo//bar//".toUTF8.data⟩).data == "../../foo/bar/".toUTF8.data
#guard (normalisePathWin ⟨"\\dir\\foo\\\\bar".toUTF8.data⟩).data == "/dir/foo/bar".toUTF8.data
#guard (normalisePathWin ⟨"..\\".toUTF8.data⟩).data == "../".toUTF8.data
#guard (utf8toUnicode ⟨#[0x61, 0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80, 0x62]⟩).data == "a%u00e9%u20ac%u1f600b".toUTF8.data
#guard (utf8toUnicode ⟨#[0x61, 0xC3]⟩).data == #[0x61, 0xC3]
#guard (utf8toUnicode ⟨#[0xC0, 0x80, 0xED, 0xA0, 0x80, 0x00, 0xC3]⟩).data == #[0xC0, 0x80, 0xED, 0xA0, 0x80, 0x00, 0xC3]
```

- [ ] **Step 2: Definitions**

```lean
/-- `normalisePath` / `normalisePathWin`. A transcription of msc_util.c
`normalize_path_inplace`: `src` walks the input, `out` is the output written so far (the C
`dst`), `hitroot` remembers a relative path that climbed above its start. Backslashes are
converted to `/` first when `win`. -/
def normalisePathWith (win : Bool) (b0 : ByteArray) : ByteArray := Id.run do
  if b0.size == 0 then return b0
  let b := if win then mapBytes (fun x => if x == '\\'.toUInt8 then '/'.toUInt8 else x) b0 else b0
  let last := b.size - 1
  let slash := '/'.toUInt8
  let dot := '.'.toUInt8
  let relative := b[0]! != slash
  let trailing := b[last]! == slash
  let mut src := 0
  let mut out : Array UInt8 := #[]
  let mut hitroot := false
  let mut done := false
  while !done && src ≤ last && out.size ≤ last do
    let c := b[src]!
    let mut copy := true
    if src == last then done := true
    if done || byteAt b (src + 1) == some slash then
      if src != last && c == slash then
        pure ()                                              -- empty segment: copy skips it
      else if c == dot then
        if out.size > 0 && out[out.size - 1]! == dot then     -- back-reference
          if relative && (hitroot || out.size ≤ 2) then
            hitroot := true
          else
            let mut d := out.size - 3
            while d > 0 && out[d]! != slash do d := d - 1
            if d == 0 then
              hitroot := true
              d := if !relative && src == last then 1 else 0
            out := out.extract 0 d
            if done then copy := false else src := src + 1
        else if out.size == 0 then                            -- relative self-reference
          if done then copy := false else src := src + 1
        else if out[out.size - 1]! == slash then              -- self-reference
          if done then copy := false
          else
            out := out.pop
            src := src + 1
      else if out.size > 0 then
        hitroot := false
    if copy then
      if b[src]! == slash then
        while src < last && b[src + 1]! == slash do src := src + 1
        if relative && out.size == 0 then
          src := src + 1
          copy := false
      if copy then
        out := out.push b[src]!
        src := src + 1
  if !trailing && out.size > 0 && out[out.size - 1]! == slash then out := out.pop
  return ⟨out⟩

def normalisePath : ByteArray → ByteArray := normalisePathWith false
def normalisePathWin : ByteArray → ByteArray := normalisePathWith true

/-- A well-formed multi-byte UTF-8 sequence at `i` (RFC 3629: continuation bytes, no
overlong form, no surrogate, at most U+10FFFF): its length and code point. -/
def utf8Seq (b : ByteArray) (i : Nat) : Option (Nat × Nat) := do
  let c := (← byteAt b i).toNat
  let cont (k : Nat) : Option Nat := do
    let x := (← byteAt b (i + k)).toNat
    if x &&& 0xC0 == 0x80 then some (x &&& 0x3F) else none
  if c &&& 0xE0 == 0xC0 then
    let d := ((c &&& 0x1F) <<< 6) ||| (← cont 1)
    if d < 0x80 then none else some (2, d)
  else if c &&& 0xF0 == 0xE0 then
    let d := ((c &&& 0x0F) <<< 12) ||| ((← cont 1) <<< 6) ||| (← cont 2)
    if d < 0x800 || (0xD800 ≤ d && d ≤ 0xDFFF) then none else some (3, d)
  else if c &&& 0xF8 == 0xF0 then
    let d := ((c &&& 0x07) <<< 18) ||| ((← cont 1) <<< 12) ||| ((← cont 2) <<< 6) ||| (← cont 3)
    if d < 0x10000 || d > 0x10FFFF then none else some (4, d)
  else none

/-- `%u` followed by at least four lowercase hexadecimal digits of `d`. -/
def pushUni (out : ByteArray) (d : Nat) : ByteArray := Id.run do
  let digits := Nat.toDigits 16 d
  let mut o := (out.push '%'.toUInt8).push 'u'.toUInt8
  for _ in [:4 - min 4 digits.length] do o := o.push '0'.toUInt8
  for ch in digits do o := o.push ch.toNat.toUInt8
  return o

/-- `utf8toUnicode`: each well-formed multi-byte sequence becomes `%uXXXX`; every other byte
is copied. msc_util.c `utf8_unicode_inplace_ex` for well-formed input; its NUL handling
and v3's differ from the prose and from each other (`spec/07#utf8tounicode`). -/
def utf8toUnicode (b : ByteArray) : ByteArray := go 0 .empty
where
  go (i : Nat) (out : ByteArray) : ByteArray :=
    if h : i < b.size then
      match utf8Seq b i with
      | some (len, d) => go (i + len) (pushUni out d)
      | none => go (i + 1) (out.push b[i])
    else out
  termination_by b.size - i
```

(If `termination_by` cannot see that `len ≥ 2`, restructure `go` to match on the three lengths explicitly: `| some (2, d) => go (i + 2) …`, `| some (3, d) => …`, `| some (4, d) => …`, `| _ => go (i + 1) …`.)

- [ ] **Step 3: Spec** — `utf8toUnicode` divergence notes: `**Divergence notes.** A NUL byte is ASCII and is left unchanged by Coraza, as specified; ModSecurity v2 (\`utf8_unicode_inplace_ex\`) treats NUL as the lead byte of a two-byte sequence and emits \`%u00XX\` when the next byte is 0x80 or above, and libmodsecurity v3 (\`utf8_to_unicode.cc\`) drops a NUL that is not the last byte. No corpus case contains a NUL.`
- [ ] **Step 4: Register, run** — `formalized` gains `normalisePath`, `normalisePathWin`, `utf8toUnicode`. `lake exe seclang-check` → every line `N passed, 0 failed`, no `skipped`, exit 0. Validator 0.
- [ ] **Step 5: Commit** — `feat(formal): normalisePath, normalisePathWin, utf8toUnicode; spec: utf8toUnicode NUL divergences`.

---

### Task 7: Docs and full verification

**Files:**
- Modify: `formal/README.md`, `AGENTS.md` (`formal/` row), `README.md` (`formal/` row), `spec/07-transformations.md` (preamble sentence)

- [ ] **Step 1: Docs** — `formal/README.md`: replace "Status: spike, five transformations" with "Status: every transformation of `spec/07-transformations.md` (`SecLang/Transformations.lean`, digests in `SecLang/Digest.lean`); design documents under `docs/superpowers/specs/2026-10-08-lean-*.md`." `AGENTS.md` row: "`SecLang/Transformations.lean` defines every transformation of spec 07 over `ByteArray`". `README.md` row: "Lean 4 model of the specification, run against the unit-tier corpus in CI (`lake exe seclang-check`). Covers every transformation of spec 07." Spec 07 preamble: "The Lean definitions in `formal/SecLang/Transformations.lean` are the executable reference for the behaviour this chapter defines" (drop "in the transformations they cover").
- [ ] **Step 2: Full verification** — from the repo root: `uv run python tools/validate.py` (0 errors); `uv run python -m unittest discover -s tools -t .` (OK); `(cd adapters/coraza && go test ./... -count=1)` (ok); `(cd formal && lake build && lake exe seclang-check; echo $?)` (36 files, 0 failed, exit 0); `hugo -s site --gc --minify --cleanDestinationDir && site/smoke.sh` (passes).
- [ ] **Step 3: Commit** — `docs: formal/ covers every transformation`.

---

### Task 8: Branch review and finish

- [ ] **Step 1: Ledger** — collect rulings and triage results for the final summary.
- [ ] **Step 2: Whole-branch review** — fresh reviewer (most capable model) on `main..formal-transformations` with the design doc, this plan's Review Focus, and the ledger's rulings; one fix pass.
- [ ] **Step 3: Finish** — `superpowers:finishing-a-development-branch`; standing choice: merge to main locally, never push.
