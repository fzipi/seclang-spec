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

/-- A unit-tier byte string (every code point ≤ U+00FF, one byte each; `tests/README.md`). -/
def toBytes (s : String) : Except String ByteArray := do
  let mut out := ByteArray.emptyWithCapacity s.length
  for c in s.toList do
    if c.toNat > 255 then throw s!"not a byte string: {s.quote}"
    out := out.push c.toNat.toUInt8
  return out

/-- The bytes of a Latin-1 byte string (inverse of `ofBytes`). -/
def bytesOf (s : String) : ByteArray := ⟨(s.toList.map (·.toNat.toUInt8)).toArray⟩

def ofBytes (b : ByteArray) : String :=
  String.ofList (b.toList.map fun x => Char.ofNat x.toNat)

end SecLang
