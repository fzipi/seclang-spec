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

end SecLang
