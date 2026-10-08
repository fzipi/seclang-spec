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
