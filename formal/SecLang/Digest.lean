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
    let mut w : Array UInt32 := Array.replicate 80 0
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

#guard (hexEncode (md5 ⟨#[]⟩)).data == "d41d8cd98f00b204e9800998ecf8427e".toUTF8.data
#guard (hexEncode (md5 ⟨"TestCase".toUTF8.data⟩)).data == "c9aba2c3e60126169e80e9a26ba273c1".toUTF8.data
#guard (hexEncode (md5 ⟨(List.replicate 64 0x61).toArray⟩)).data == "014842d480b571495a4a0363793f7367".toUTF8.data
#guard (hexEncode (sha1 ⟨#[]⟩)).data == "da39a3ee5e6b4b0d3255bfef95601890afd80709".toUTF8.data
#guard (hexEncode (sha1 ⟨"TestCase".toUTF8.data⟩)).data == "a70ce38389e318bd2be18a0111c6dc76bd2cd9ed".toUTF8.data
#guard (hexEncode (sha1 ⟨(List.replicate 64 0x61).toArray⟩)).data == "0098ba824b5c16427bd7a1122a5a442a25ec644d".toUTF8.data

/-- The transformations the model defines, by corpus name. -/
def byName : List (String × (ByteArray → ByteArray)) :=
  [("lowercase", lowercase), ("hexEncode", hexEncode), ("urlDecodeUni", urlDecodeUni),
   ("cssDecode", cssDecode), ("base64Decode", base64Decode),
   ("uppercase", uppercase), ("removeNulls", removeNulls), ("replaceNulls", replaceNulls),
   ("removeWhitespace", removeWhitespace), ("trimLeft", trimLeft), ("trimRight", trimRight),
   ("trim", trim), ("length", length), ("parityEven7bit", parityEven7bit),
   ("parityOdd7bit", parityOdd7bit), ("parityZero7bit", parityZero7bit),
   ("compressWhitespace", compressWhitespace), ("hexDecode", hexDecode), ("urlDecode", urlDecode),
   ("urlEncode", urlEncode), ("sqlHexDecode", sqlHexDecode),
   ("base64Encode", base64Encode), ("base64DecodeExt", base64DecodeExt), ("md5", md5), ("sha1", sha1),
   ("cmdLine", cmdLine), ("removeCommentsChar", removeCommentsChar), ("removeComments", removeComments),
   ("replaceComments", replaceComments), ("escapeSeqDecode", escapeSeqDecode), ("jsDecode", jsDecode),
   ("htmlEntityDecode", htmlEntityDecode), ("normalisePath", normalisePath),
   ("normalisePathWin", normalisePathWin), ("utf8toUnicode", utf8toUnicode)]

end SecLang
