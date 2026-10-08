import SecLang.Request
import SecLang.Regex
/-! Operators (`spec/06-operators.md`) over byte strings, parametric in the regular-expression
oracle. `verifyCC`, `verifyCPF` and `verifySSN` follow ModSecurity v2 `apache2/re_operators.c`,
which libmodsecurity v3 ports; Coraza does not implement them. -/
namespace SecLang

/-- The regular-expression oracle: leftmost match at or after an offset, as group positions
(`Regex.searchAt` instantiates it). -/
structure Oracle where
  rxAt : String → ByteArray → Nat → Option (Array (Option (Nat × Nat)))

/-- Groups as byte slices from offset 0. -/
def Oracle.rx (o : Oracle) (re : String) (v : ByteArray) : Option (Array (Option ByteArray)) :=
  (o.rxAt re v 0).map fun caps => caps.map fun
    | some (a, b) => some (v.extract a b)
    | none => none

/-- C `atoi`: optional sign and leading digits, 0 otherwise (`06#eq`). -/
def atoi (b : ByteArray) : Int :=
  let cs := (ofBytes b).toList.dropWhile isBlank
  let (neg, cs) := match cs with | '-' :: r => (true, r) | '+' :: r => (false, r) | _ => (false, cs)
  let n : Int := ((String.ofList (cs.takeWhile Char.isDigit)).toNat?).getD 0
  if neg then -n else n

def containsBytes (hay needle : ByteArray) : Bool :=
  let h := hay.toList
  let n := needle.toList
  (List.range (h.length + 1)).any fun i => n.isPrefixOf (h.drop i)

/-- `@pm` phrases: space-separated, `|hex|` runs decoded. -/
partial def pmPhrases (param : ByteArray) : List ByteArray :=
  ((ofBytes param).splitOn " ").filterMap fun p => if p.isEmpty then none else some (pmDecode p.toList .empty)
where
  pmDecode : List Char → ByteArray → ByteArray
    | '|' :: rest, acc =>
      let hex := rest.takeWhile (· != '|')
      pmDecode ((rest.dropWhile (· != '|')).drop 1) (acc ++ hexDecode (String.ofList hex).toUTF8)
    | c :: rest, acc => pmDecode rest (acc.push c.toNat.toUInt8)
    | [], acc => acc

def ipv4 (s : String) : Option Nat :=
  match (s.splitOn ".").mapM natOf? with
  | some [a, b, c, d] => if a ≤ 255 && b ≤ 255 && c ≤ 255 && d ≤ 255 then some (((a * 256 + b) * 256 + c) * 256 + d) else none
  | _ => none

def hexGroupValue (h : String) : Nat := h.toList.foldl (fun acc c => acc * 16 + ((hexVal c.toNat.toUInt8).getD 0).toNat) 0

def v6Groups (g : String) : Option (List Nat) :=
  if g.isEmpty then some [] else
  (g.splitOn ":").mapM fun h => if isHexGroup h then some (hexGroupValue h) else none

/-- Groups of a run that may end in a dotted quad (two groups). -/
def v6Tail (g : String) : Option (List Nat) :=
  match (g.splitOn ":").getLast? with
  | some last =>
    if last.contains '.' then do
      let v4 ← ipv4 last
      let head ← v6Groups (":".intercalate (g.splitOn ":").dropLast)
      some (head ++ [v4 / 65536, v4 % 65536])
    else v6Groups g
  | none => v6Groups g

def ipv6 (s : String) : Option Nat :=
  let expand (gs : List Nat) : Nat := gs.foldl (fun acc g => acc * 65536 + g) 0
  match s.splitOn "::" with
  | [a] => (v6Tail a).bind fun gs => if gs.length == 8 then some (expand gs) else none
  | [a, b] => do
    let x ← v6Groups a
    let y ← v6Tail b
    if x.length + y.length ≤ 7 then some (expand (x ++ List.replicate (8 - x.length - y.length) 0 ++ y)) else none
  | _ => none

/-- `@ipMatch` (`06#ipmatch`): the value as an address inside any listed address or network. -/
def ipMatch (param : ByteArray) (v : ByteArray) : Bool :=
  let value := ofBytes v
  (((ofBytes param).splitOn ",").map trimBlanks).any fun e =>
    let (addr, pfx) := match e.splitOn "/" with | [a] => (a, none) | [a, p] => (a, natOf? p) | _ => ("", none)
    if addr.contains ':' then
      match ipv6 addr, ipv6 value with
      | some net, some ip => let shift := 128 - pfx.getD 128; net >>> shift == ip >>> shift
      | _, _ => false
    else
      match ipv4 addr, ipv4 value with
      | some net, some ip => let shift := 32 - pfx.getD 32; net >>> shift == ip >>> shift
      | _, _ => false

def validUrlEncoding (v : ByteArray) : Bool := go 0
where
  go (i : Nat) : Bool :=
    if i < v.size then
      if v[i]! == '%'.toUInt8 then (hexAt v (i + 1)).isSome && (hexAt v (i + 2)).isSome && go (i + 3) else go (i + 1)
    else true
  termination_by v.size - i

def validUtf8 (v : ByteArray) : Bool := go 0
where
  go (i : Nat) : Bool :=
    if h : i < v.size then
      if v[i] < 0x80 then go (i + 1)
      else match utf8Seq v i with
        | some (2, _) => go (i + 2) | some (3, _) => go (i + 3) | some (4, _) => go (i + 4) | _ => false
    else true
  termination_by v.size - i

def isWordByte (b : UInt8) : Bool := isAlnum b || b == '_'.toUInt8

/-- `containsWord` (v2 `msre_op_containsWord_execute`): the parameter at a position preceded
by the start or a non-word byte and followed by the end or a non-word byte; word bytes are
ASCII alphanumerics and `_`; the empty parameter matches. -/
def containsWord (v param : ByteArray) : Bool :=
  if param.size == 0 then true else
  let h := v.toList
  let n := param.toList
  (List.range (h.length + 1)).any fun i =>
    n.isPrefixOf (h.drop i) &&
    (i == 0 || !isWordByte (h.getD (i - 1) 0)) &&
    (i + n.length == h.length || !isWordByte (h.getD (i + n.length) 0))

/-- Luhn over the digits of `s` (v2 `luhn_verify`); false without a digit. -/
def luhn (s : ByteArray) : Bool :=
  let digits := (s.toList.filter isDigit).map fun b => b.toNat - 48
  if digits.isEmpty then false else
  let (sum, _) := digits.reverse.foldl (fun (acc, double) d =>
      (acc + (if double then (let x := d * 2; if x > 9 then x - 9 else x) else d), !double)) (0, false)
  sum % 10 == 0

/-- Brazilian CPF (v2 `cpf_verify`): exactly eleven digits taken from the match, not a trivial
sequence, check digits agreeing with the weighted sums. -/
def cpfValid (s : ByteArray) : Bool :=
  let ds := ((s.toList.filter isDigit).map fun b => b.toNat - 48).take 11
  if ds.length != 11 then false else
  let trivial := (List.range 10).map (fun d => List.replicate 11 d) ++ [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0]]
  if trivial.contains ds then false else
  let check (k : Nat) : Nat :=
    let sum := ((ds.take k).zip ((List.range k).map fun i => k + 1 - i)).foldl (fun acc (d, w) => acc + d * w) 0
    let r := sum % 11
    if r < 2 then 0 else 11 - r
  ds.getD 9 99 == check 9 && ds.getD 10 99 == check 10

/-- US SSN (v2 `ssn_verify`): nine digits, not all ascending by one nor all equal, area, group
and serial non-zero, area not 666 and below 740. -/
def ssnValid (s : ByteArray) : Bool :=
  let ds := (s.toList.filter isDigit).map fun b => b.toNat - 48
  if ds.length != 9 then false else
  let pairs := ds.zip ds.tail
  if pairs.all (fun (a, b) => b == a + 1) || pairs.all (fun (a, b) => a == b) then false else
  let num (xs : List Nat) : Nat := xs.foldl (fun acc d => acc * 10 + d) 0
  let area := num (ds.take 3)
  let grp := num ((ds.drop 3).take 2)
  let serial := num (ds.drop 5)
  area != 0 && grp != 0 && serial != 0 && area != 666 && area < 740

/-- `verify*` scan (v2): regex matches from offset 0 upward with anchors relative to the whole
value, the whole match checked by `ok`; after a failing match the search resumes one past its
start. An empty match does not count (PCRE `NOTEMPTY`). -/
def verifyWith (o : Oracle) (ok : ByteArray → Bool) (re : String) (v : ByteArray) : Bool := go 0 (v.size + 1)
where
  go (offset fuel : Nat) : Bool :=
    match fuel with
    | 0 => false
    | fuel + 1 =>
      if offset ≥ v.size then false else
      match o.rxAt re v offset with
      | some caps => match caps[0]! with
        | some (a, b) => if b > a && ok (v.extract a b) then true else go (a + 1) fuel
        | none => false
      | none => false

/-- One operator against one value (`06`); `@rx` through the oracle, with its groups. -/
def evalOperator (o : Oracle) (name : String) (param : ByteArray) (v : ByteArray) : Bool × Option (Array (Option ByteArray)) :=
  match name with
  | "rx" => match o.rx (ofBytes param) v with | some g => (true, some g) | none => (false, none)
  | "streq" => (v.data == param.data, none)
  | "contains" => (containsBytes v param, none)
  | "beginsWith" => (param.toList.isPrefixOf v.toList, none)
  | "endsWith" => (param.toList.reverse.isPrefixOf v.toList.reverse, none)
  | "within" => (containsBytes param v, none)
  | "eq" => (atoi v == atoi param, none)
  | "ge" => (decide (atoi v ≥ atoi param), none)
  | "gt" => (decide (atoi v > atoi param), none)
  | "le" => (decide (atoi v ≤ atoi param), none)
  | "lt" => (decide (atoi v < atoi param), none)
  | "pm" => ((pmPhrases param).any fun p => containsBytes (lowercase v) (lowercase p), none)
  | "unconditionalMatch" => (true, none)
  | "validateByteRange" =>
    let ranges := ((ofBytes param).splitOn ",").filterMap fun r => match r.splitOn "-" with
      | [a] => (natOf? a).map fun n => (n, n)
      | [a, b] => match natOf? a, natOf? b with | some x, some y => some (x, y) | _, _ => none
      | _ => none
    (v.toList.any fun b => !ranges.any fun (lo, hi) => lo ≤ b.toNat && b.toNat ≤ hi, none)
  | "validateUrlEncoding" => (!validUrlEncoding v, none)
  | "validateUtf8Encoding" => (!validUtf8 v, none)
  | "ipMatch" => (ipMatch param v, none)
  | "containsWord" => (containsWord v param, none)
  | "strmatch" => (containsBytes v param, none)
  | "noMatch" => (false, none)
  | "verifyCC" => (verifyWith o luhn (ofBytes param) v, none)
  | "verifyCPF" => (verifyWith o cpfValid (ofBytes param) v, none)
  | "verifySSN" => (verifyWith o ssnValid (ofBytes param) v, none)
  | _ => (false, none)

/-- Operators the model defines (`06`); the runner skips the others by name. -/
def implemented : List String :=
  ["beginsWith", "contains", "containsWord", "endsWith", "eq", "ge", "gt", "ipMatch", "le", "lt", "noMatch",
   "pm", "rx", "streq", "strmatch", "unconditionalMatch", "validateByteRange", "validateUrlEncoding",
   "validateUtf8Encoding", "verifyCC", "verifyCPF", "verifySSN", "within"]

def testOracle : Oracle := ⟨Regex.searchAt⟩


#guard (evalOperator testOracle "containsWord" "abc".toUTF8 "abc def".toUTF8).1
#guard !(evalOperator testOracle "containsWord" "abc".toUTF8 "abcdef".toUTF8).1
#guard !(evalOperator testOracle "containsWord" "abc".toUTF8 "x_abc".toUTF8).1
#guard (evalOperator testOracle "containsWord" "abc".toUTF8 "x\u0000abc".toUTF8).1
#guard (evalOperator testOracle "containsWord" "".toUTF8 "".toUTF8).1
#guard (evalOperator testOracle "strmatch" "def".toUTF8 "abcdefghi".toUTF8).1
#guard !(evalOperator testOracle "noMatch" "".toUTF8 "x".toUTF8).1
#guard (evalOperator testOracle "verifyCC" "(?:^|[^\\d])(\\d+)(?:[^\\d]|$)".toUTF8 "a5484605089158216b".toUTF8).1
#guard !(evalOperator testOracle "verifyCC" "(?:^|[^\\d])(\\d+)(?:[^\\d]|$)".toUTF8 "1234567890012345".toUTF8).1
#guard !(evalOperator testOracle "verifyCC" "(?:^|[^\\d])(\\d{4}\\-?\\d{4}\\-?\\d{2}\\-?\\d{2}\\-?\\d{1,4})(?:[^\\d]|$)".toUTF8 "15484605089158216".toUTF8).1
#guard (evalOperator testOracle "verifyCC" "(?:^|[^\\d])(\\d{4}\\-?\\d{4}\\-?\\d{2}\\-?\\d{2}\\-?\\d{1,4})(?:[^\\d]|$)".toUTF8 "5484-6050-8915-8216".toUTF8).1
#guard !(evalOperator testOracle "verifyCC" "\\d*".toUTF8 "".toUTF8).1
#guard (evalOperator testOracle "verifyCPF" "([0-9]{3}\\.){2}[0-9]{3}-[0-9]{2}".toUTF8 "asdf 010.817.514-60 asdf".toUTF8).1
#guard !(evalOperator testOracle "verifyCPF" "([0-9]{3}\\.){2}[0-9]{3}-[0-9]{2}".toUTF8 "asdf 010.817 asdf".toUTF8).1
#guard (evalOperator testOracle "verifySSN" "\\d{3}-?\\d{2}-?\\d{4}".toUTF8 "asdf 574-57-8065 asdf".toUTF8).1
#guard !(evalOperator testOracle "verifySSN" "\\d{3}-?\\d{2}-?\\d{4}".toUTF8 "800-57-8065".toUTF8).1
#guard !(evalOperator testOracle "verifySSN" "\\d{3}-?\\d{2}-?\\d{4}".toUTF8 "123-45-6789".toUTF8).1
#guard (evalOperator testOracle "rx" "(a)(b?)(c)".toUTF8 "ac".toUTF8).2.map (·.toList.map (·.map ofBytes)) == some [some "ac", some "a", some "", some "c"]

end SecLang
