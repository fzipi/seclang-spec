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

#guard (urlDecodeUni ⟨"Test+Case".toUTF8.data⟩).data == "Test Case".toUTF8.data
#guard (urlDecodeUni ⟨"%41%ff%u0042".toUTF8.data⟩).data == #[0x41, 0xFF, 0x42]
#guard (urlDecodeUni ⟨"%uff01%uff5e%uff00%uff7f".toUTF8.data⟩).data == #[0x21, 0x7E, 0x00, 0x7F]
#guard (urlDecodeUni ⟨"%u1141".toUTF8.data⟩).data == #[0x41]
#guard (urlDecodeUni ⟨"%u00%u0020".toUTF8.data⟩).data == "%u00 ".toUTF8.data
#guard (urlDecodeUni ⟨"%0g%20%%%".toUTF8.data⟩).data == "%0g %%%".toUTF8.data
#guard (urlDecodeUniWith (fun c => if c == 0x1141 then some 0x5A else none) ⟨"%u1141".toUTF8.data⟩).data == #[0x5A]

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

#guard (cssDecode ⟨"\\a\\b\\n\\?\\12\\123\\1234\\ff01\\ff5e".toUTF8.data⟩).data
  == #[0x0A, 0x0B, 0x6E, 0x3F, 0x12, 0x23, 0x34, 0x21, 0x7E]
#guard (cssDecode ⟨"\\1A\\1 A\\1234567\\123456 7\\1x\\1 x".toUTF8.data⟩).data
  == #[0x1A, 0x01, 0x41, 0x56, 0x37, 0x56, 0x37, 0x01, 0x78, 0x01, 0x78]
#guard (cssDecode ⟨"\\\n\\\u0000  s\\".toUTF8.data⟩).data == #[0x00, 0x20, 0x20, 0x73]
#guard (cssDecode ⟨"\\  x".toUTF8.data⟩).data == #[0x20, 0x20, 0x78]
#guard (cssDecode ⟨"\\0ff21\\00ff21\\1ff21".toUTF8.data⟩).data == #[0x41, 0x41, 0x21]

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

#guard (base64Decode ⟨"VGVzdENhc2U=".toUTF8.data⟩).data == "TestCase".toUTF8.data
#guard (base64Decode ⟨"VGVzdENhc2Ux".toUTF8.data⟩).data == "TestCase1".toUTF8.data
#guard (base64Decode ⟨"VGVzdABDYXNl".toUTF8.data⟩).data == #[0x54, 0x65, 0x73, 0x74, 0x00, 0x43, 0x61, 0x73, 0x65]
#guard (base64Decode ⟨"VGVzdENhc2U".toUTF8.data⟩).data == "TestCase".toUTF8.data
#guard (base64Decode ⟨"VGVzdENhc2UxV".toUTF8.data⟩).data == "TestCase1".toUTF8.data
#guard (base64Decode ⟨"VGVz*dENh".toUTF8.data⟩).data == "Tes".toUTF8.data
#guard (base64Decode ⟨#[0x56, 0x47, 0x56, 0x7A, 0x00, 0x64]⟩).data == "Tes".toUTF8.data
#guard (base64Decode ⟨#[]⟩).data == #[]

end SecLang
