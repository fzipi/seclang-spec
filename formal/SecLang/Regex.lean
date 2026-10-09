import SecLang.Bytes
/-! A matcher for the Core `@rx` subset (`spec/06-operators.md#rx`): literals, `.`, classes,
`\d \w \s` and their negations, `\b`, anchors, alternation, `(...)`, `(?:...)`,
`(?P<name>...)`, greedy and lazy `* + ? {m,n}`, flags `(?i)`, `(?s)`, `(?m)`. Backtracking
over the subject's bytes read as Latin-1 characters. This is the oracle `Semantics.lean`
is parametric in; ADR-0018 defers the full dialect. -/
namespace SecLang.Regex

inductive ClassItem
  | ch (c : Char) | range (lo hi : Char) | digit (neg : Bool) | word (neg : Bool) | space (neg : Bool)
  deriving Repr

structure Flags where
  ci : Bool := false
  dotAll : Bool := false
  multi : Bool := false
  deriving Repr, BEq

inductive Re
  | lit (c : Char)
  | any
  | cls (neg : Bool) (items : List ClassItem)
  | bol | eol
  | wordB (neg : Bool)
  | group (cap : Option Nat) (r : Re)
  | alt (a b : Re)
  | seq (rs : List Re)
  | rep (r : Re) (min : Nat) (max : Option Nat) (greedy : Bool)
  | flagged (f : Flags) (r : Re)          -- the flags in force inside `r`
  deriving Repr


def isWordC (c : Char) : Bool := c.isAlphanum || c == '_'
def isSpaceC (c : Char) : Bool := c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\x0c' || c == '\x0b'

def escapeItem : Char → Option ClassItem
  | 'd' => some (.digit false) | 'D' => some (.digit true) | 'w' => some (.word false)
  | 'W' => some (.word true) | 's' => some (.space false) | 'S' => some (.space true) | _ => none

def escapeChar : Char → Char
  | 'n' => '\n' | 't' => '\t' | 'r' => '\r' | 'f' => '\x0c' | 'v' => '\x0b' | 'e' => '\x1b' | c => c

def hexChar (a b : Char) : Option Char := do
  if !(a.isAlphanum && b.isAlphanum) then none
  let x ← hexVal a.toNat.toUInt8
  let y ← hexVal b.toNat.toUInt8
  some (Char.ofNat (x.toNat * 16 + y.toNat))

/-- Parser state: remaining pattern, the next capture index and the flags in force. -/
structure P where
  rest : List Char
  next : Nat := 1
  flags : Flags := {}
  base : Flags := {}   -- the flags the matcher starts with; atoms are wrapped only when `flags` differ

def withLetters (f : Flags) (letters : List Char) : Flags :=
  { ci := f.ci || letters.contains 'i', dotAll := f.dotAll || letters.contains 's', multi := f.multi || letters.contains 'm' }

def parseNat (cs : List Char) : Nat × List Char :=
  let ds := cs.takeWhile Char.isDigit
  ((String.ofList ds).toNat?.getD 0, cs.drop ds.length)

/-- `{m}`, `{m,}`, `{m,n}` after the opening brace. -/
def parseBraces (cs : List Char) : Option (Nat × Option Nat × List Char) :=
  match cs with
  | c :: _ => if !c.isDigit then none else
    let (m, cs) := parseNat cs
    match cs with
    | '}' :: rest => some (m, some m, rest)
    | ',' :: '}' :: rest => some (m, none, rest)
    | ',' :: rest =>
      let (n, rest) := parseNat rest
      match rest with | '}' :: r => some (m, some n, r) | _ => none
    | _ => none
  | [] => none

/-- Hex digits to a number (for `\x{hh}`). -/
def hexGroupValue' (cs : List Char) : Nat :=
  cs.foldl (fun acc c => acc * 16 + (if c.isDigit then c.toNat - '0'.toNat else (c.toLower.toNat - 'a'.toNat + 10))) 0

/-- `\x{hh}` after the backslash and `x`: one byte, braced (shared by PCRE, PCRE2 and RE2). -/
def bracedHex : List Char → Except String (Char × List Char)
  | '{' :: rest =>
    let hex := rest.takeWhile (· != '}')
    match rest.drop hex.length with
    | '}' :: rest' =>
      if hex.isEmpty || hex.length > 2 || !hex.all (fun c => c.isDigit || "abcdefABCDEF".contains c) then .error "bad \\x{} escape (one byte)"
      else .ok (Char.ofNat (hexGroupValue' hex), rest')
    | _ => .error "bad \\x{} escape"
  | _ => .error "bad \\x{} escape"

/-- One atom of a `[...]` class: a literal (possibly `\xhh`, `\x{hh}` or an escaped character)
or a class escape such as `\d`. -/
def classAtom : List Char → Except String (Sum Char ClassItem × List Char)
  | [] => .error "unterminated class"
  | '\\' :: 'x' :: '{' :: rest => (bracedHex ('{' :: rest)).map fun (c, r) => (.inl c, r)
  | '\\' :: 'x' :: a :: b :: rest =>
    match hexChar a b with
    | some c => .ok (.inl c, rest)
    | none => .error "bad \\x escape"
  | '\\' :: c :: rest =>
    match escapeItem c with
    | some it => .ok (.inr it, rest)
    | none => .ok (.inl (escapeChar c), rest)
  | c :: rest => .ok (.inl c, rest)

/-- A `[...]` class after the opening bracket (and `^`); `fuel` bounds the items. -/
def parseClass (fuel : Nat) (cs : List Char) (acc : List ClassItem) (first : Bool) : Except String (List ClassItem × List Char) :=
  match fuel with
  | 0 => .error "class too long"
  | fuel + 1 =>
    match cs with
    | [] => .error "unterminated class"
    | ']' :: rest => if first then parseClass fuel rest (.ch ']' :: acc) false else .ok (acc.reverse, rest)
    | _ => do
      let (a, rest) ← classAtom cs
      match a with
      | .inr it => parseClass fuel rest (it :: acc) false
      | .inl a =>
        match rest with
        | '-' :: ']' :: rest' => .ok ((.ch '-' :: .ch a :: acc).reverse, rest')   -- a trailing `-` is literal
        | '-' :: rest' =>
          match classAtom rest' with
          | .ok (.inl b, rest'') => parseClass fuel rest'' (.range a b :: acc) false
          | _ => parseClass fuel rest' (.ch '-' :: .ch a :: acc) false   -- `a-\d`: the dash is literal
        | _ => parseClass fuel rest (.ch a :: acc) false

mutual
def parseAlt (fuel : Nat) (p : P) : Except String (Re × P) :=
  match fuel with
  | 0 => .error "pattern too complex"
  | fuel + 1 => do
  let (rs, p) ← parseSeq fuel p
  match p.rest with
  | '|' :: rest =>
    let (r2, p2) ← parseAlt fuel { p with rest }
    return (.alt (.seq rs) r2, p2)
  | _ => return (.seq rs, p)

def parseSeq (fuel : Nat) (p : P) : Except String (List Re × P) :=
  match fuel with
  | 0 => .error "pattern too complex"
  | fuel + 1 => do
  match p.rest with
  | [] | ')' :: _ | '|' :: _ => return ([], p)
  | _ =>
    let (a, p) ← parseQuantified fuel p
    let (rs, p) ← parseSeq fuel p
    return (a :: rs, p)

def parseQuantified (fuel : Nat) (p : P) : Except String (Re × P) :=
  match fuel with
  | 0 => .error "pattern too complex"
  | fuel + 1 => do
  let (a, p) ← parseAtom fuel p
  let a := if p.flags == p.base then a else .flagged p.flags a
  let q : Option (Nat × Option Nat × List Char) := match p.rest with
    | '*' :: rest => some (0, none, rest)
    | '+' :: rest => some (1, none, rest)
    | '?' :: rest => some (0, some 1, rest)
    | '{' :: rest => parseBraces rest
    | _ => none
  match q with
  | none => return (a, p)
  | some (mn, mx, rest) =>
    match rest with
    | '?' :: rest' => return (.rep a mn mx false, { p with rest := rest' })
    | _ => return (.rep a mn mx true, { p with rest })

def parseAtom (fuel : Nat) (p : P) : Except String (Re × P) :=
  match fuel with
  | 0 => .error "pattern too complex"
  | fuel + 1 => do
  match p.rest with
  | '(' :: '?' :: ':' :: rest => parseGroup fuel none { p with rest }
  | '(' :: '?' :: 'P' :: '<' :: rest =>
    let rest := (rest.dropWhile (· != '>')).drop 1
    parseGroup fuel (some p.next) { rest, next := p.next + 1 }
  | '(' :: '?' :: rest =>
    -- `(?flags:…)` scopes the flags to the group; `(?flags)` sets them for the rest of the enclosing group
    let letters := rest.takeWhile fun c => c == 'i' || c == 's' || c == 'm'
    if letters.isEmpty then .error "group syntax outside the Core subset" else
    let f' := withLetters p.flags letters
    match rest.drop letters.length with
    | ':' :: rest' =>
      let (g, p') ← parseGroup fuel none { p with rest := rest', flags := f' }
      return (g, { p' with flags := p.flags })
    | ')' :: rest' => return (.seq [], { p with rest := rest', flags := f' })
    | _ => .error "group syntax outside the Core subset"
  | '(' :: rest => parseGroup fuel (some p.next) { rest, next := p.next + 1 }
  | '[' :: '^' :: rest =>
    let (items, rest) ← parseClass (rest.length + 1) rest [] true
    return (.cls true items, { p with rest })
  | '[' :: rest =>
    let (items, rest) ← parseClass (rest.length + 1) rest [] true
    return (.cls false items, { p with rest })
  | '.' :: rest => return (.any, { p with rest })
  | '^' :: rest => return (.bol, { p with rest })
  | '$' :: rest => return (.eol, { p with rest })
  | '\\' :: 'b' :: rest => return (.wordB false, { p with rest })
  | '\\' :: 'B' :: rest => return (.wordB true, { p with rest })
  -- `\A` and `\z` are the absolute anchors every engine shares (`\Z` is PCRE-only): `^`/`$` without multiline
  | '\\' :: 'A' :: rest => return (.flagged { p.flags with multi := false } .bol, { p with rest })
  | '\\' :: 'z' :: rest => return (.flagged { p.flags with multi := false } .eol, { p with rest })
  | '\\' :: c :: _ =>
    if c.isDigit || "ZQEpPGKkR".contains c then .error "escape outside the Core subset" else parseEscape fuel p
  | [] => .error "unexpected end of pattern"
  | c :: rest =>
    if c == '*' || c == '+' || c == '?' then .error "nothing to repeat" else return (.lit c, { p with rest })

/-- `\x`, `\b`, `\B`, class escapes and single-character escapes. -/
def parseEscape (fuel : Nat) (p : P) : Except String (Re × P) :=
  match fuel with
  | 0 => .error "pattern too complex"
  | _ + 1 => do
  match p.rest with
  | '\\' :: 'x' :: '{' :: rest =>   -- `\x{hh}`: braced form, shared by PCRE, PCRE2 and RE2; bytes only
    let (c, rest') ← bracedHex ('{' :: rest)
    return (.lit c, { p with rest := rest' })
  | '\\' :: 'x' :: a :: b :: rest =>
    match hexChar a b with
    | some c => return (.lit c, { p with rest })
    | none => .error "bad \\x escape"
  | '\\' :: c :: rest =>
    match escapeItem c with
    | some it => return (.cls false [it], { p with rest })
    | none => return (.lit (escapeChar c), { p with rest })
  | _ => .error "trailing backslash"

def parseGroup (fuel : Nat) (cap : Option Nat) (p : P) : Except String (Re × P) :=
  match fuel with
  | 0 => .error "pattern too complex"
  | fuel + 1 => do
  let outer := p.flags
  let (r, p) ← parseAlt fuel p
  match p.rest with
  | ')' :: rest => return (.group cap r, { p with rest, flags := outer })   -- flags set inside end with the group
  | _ => .error "missing )"
end

/-- Tree and group count of a pattern (flags live in `flagged` nodes). `@rx` is compiled
dot-all by every engine (ADR-0027); `^` and `$` see the subject ends only unless `(?m)`. -/
def compile (pat : String) (dflt : Flags := { dotAll := true }) : Except String (Flags × Re × Nat) := do
  let (r, p) ← parseAlt (8 * pat.length + 16) { rest := pat.toList, flags := dflt, base := dflt }   -- fuel: the recursion depth is linear in the pattern
  if !p.rest.isEmpty then throw "unbalanced )"
  return (dflt, r, p.next - 1)

abbrev Caps := Array (Option (Nat × Nat))

def eqc (f : Flags) (a b : Char) : Bool := a == b || (f.ci && a.toLower == b.toLower)

def classMatch (f : Flags) (neg : Bool) (items : List ClassItem) (c : Char) : Bool :=
  let inRange (lo hi x : Char) : Bool := lo ≤ x && x ≤ hi
  let hit := items.any fun it => match it with
    | .ch d => eqc f c d
    | .range lo hi => inRange lo hi c || (f.ci && (inRange lo hi c.toLower || inRange lo hi c.toUpper))
    | .digit n => c.isDigit != n
    | .word n => isWordC c != n
    | .space n => isSpaceC c != n
  hit != neg

/-- Nodes of a pattern, for the match budget. -/
def Re.size : Re → Nat
  | .group _ r | .rep r _ _ _ | .flagged _ r => 1 + r.size
  | .alt a b => 1 + a.size + b.size
  | .seq rs => 1 + (rs.map Re.size).sum
  | _ => 1

mutual
/-- Match `r` at `i`, then continue with `k`. `fuel` bounds the depth of the search: a branch
that exhausts it fails, so a search beyond the budget is no match, as a PCRE match-limit hit
is in ModSecurity (`04#secpcrematchlimit`); `searchAt` sizes it so that no Core pattern on
a request-sized subject reaches it. -/
def m (fuel : Nat) (f : Flags) (s : Array Char) (r : Re) (i : Nat) (caps : Caps) (k : Nat → Caps → Option Caps) : Option Caps :=
  match fuel with
  | 0 => none
  | fuel + 1 =>
  match r with
  | .lit c => if h : i < s.size then (if eqc f s[i] c then k (i + 1) caps else none) else none
  | .any => if h : i < s.size then (if s[i] == '\n' && !f.dotAll then none else k (i + 1) caps) else none
  | .cls neg items => if h : i < s.size then (if classMatch f neg items s[i] then k (i + 1) caps else none) else none
  | .bol => if i == 0 || (f.multi && s[i - 1]! == '\n') then k i caps else none
  | .eol => if i == s.size || (f.multi && i < s.size && s[i]! == '\n') then k i caps else none   -- v2 DOLLAR_ENDONLY
  | .wordB neg =>
    let before := i > 0 && isWordC s[i - 1]!
    let after := i < s.size && isWordC s[i]!
    if (before != after) != neg then k i caps else none
  | .group cap r => m fuel f s r i caps fun j caps' => k j (match cap with | some n => caps'.setIfInBounds n (some (i, j)) | none => caps')
  | .alt a b => match m fuel f s a i caps k with | some c => some c | none => m fuel f s b i caps k
  | .seq [] => k i caps
  | .seq (r :: rs) => m fuel f s r i caps fun j c => m fuel f s (.seq rs) j c k
  | .rep r mn mx greedy => repM fuel f s r mn mx greedy i caps k 0
  | .flagged f' r => m fuel f' s r i caps k

def repM (fuel : Nat) (f : Flags) (s : Array Char) (r : Re) (mn : Nat) (mx : Option Nat) (greedy : Bool)
    (i : Nat) (caps : Caps) (k : Nat → Caps → Option Caps) (count : Nat) : Option Caps :=
  match fuel with
  | 0 => none
  | fuel + 1 =>
  let canMore : Bool := match mx with | some x => decide (count < x) | none => true
  let more := fun (_ : Unit) => if canMore then
      m fuel f s r i caps (fun j c => if j == i && decide (count ≥ mn) then none else repM fuel f s r mn mx greedy j c k (count + 1))
    else none
  let stop := fun (_ : Unit) => if count ≥ mn then k i caps else none
  if greedy then (match more () with | some c => some c | none => stop ())
  else (match stop () with | some c => some c | none => more ())
end

/-! ## Theorems for ADR-0027 -/

/-- ADR-0027: under the default flags `.` matches a newline like any other byte. -/
theorem dot_matches_newline (fuel : Nat) (f : Flags) (s : Array Char) (i : Nat) (caps : Caps)
    (k : Nat → Caps → Option Caps) (h : i < s.size) (hd : f.dotAll = true) :
    m (fuel + 1) f s .any i caps k = k (i + 1) caps := by
  simp [m, h, hd]

/-- ADR-0027: without `(?m)`, `$` matches at the end of the subject only, never before an
inner newline (the v2 `DOLLAR_ENDONLY` reading the model follows). -/
theorem eol_only_at_end (fuel : Nat) (f : Flags) (s : Array Char) (i : Nat) (caps : Caps)
    (k : Nat → Caps → Option Caps) (h : i < s.size) (hm : f.multi = false) :
    m (fuel + 1) f s .eol i caps k = none := by
  have hne : (i == s.size) = false := by simpa using Nat.ne_of_lt h
  simp [m, hne, hm]

/-- Leftmost match at or after `start`, as group positions; anchors see the whole subject. -/
def searchAt (pat : String) (subject : ByteArray) (start : Nat) : Option (Array (Option (Nat × Nat))) :=
  match compile pat with
  | .error _ => none
  | .ok (f, r, n) =>
    let s : Array Char := subject.data.map fun b => Char.ofNat b.toNat
    let budget := 1024 + 16 * (s.size + 1) * (r.size + 1)   -- the match limit, see `m`
    let rec tryFrom (i : Nat) (fuel : Nat) : Option Caps :=
      match fuel with
      | 0 => none
      | fuel + 1 =>
        match m budget f s r i (Array.replicate (n + 1) none) (fun j caps => some (caps.setIfInBounds 0 (some (i, j)))) with
        | some caps => some caps
        | none => if i < s.size then tryFrom (i + 1) fuel else none
    tryFrom start (s.size + 1 - start)

/-- Leftmost match of `pat` anywhere in `subject`; groups as byte slices, `none` for a group
that did not take part or for a pattern outside the subset. -/
def search (pat : String) (subject : ByteArray) : Option (Array (Option ByteArray)) :=
  (searchAt pat subject 0).map fun caps => caps.map fun
    | some (a, b) => some (subject.extract a b)
    | none => none

/-- Guard helper: pattern and subject as strings. -/
def searchStr (pat subject : String) : Option (List (Option String)) :=
  (search pat subject.toUTF8).map fun caps => caps.toList.map (·.map ofBytes)

#guard searchStr "^user-(\\d+)$" "user-42" == some [some "user-42", some "42"]
#guard searchStr "(?i)^USER" "user-42" == some [some "user"]
#guard (searchStr "^(?:URLENCODED|MULTIPART|XML|JSON)$" "JSON").isSome
#guard (searchStr "^(?:URLENCODED|MULTIPART|XML|JSON)$" "RAW").isNone
#guard searchStr "(?i)(?:^|\\.)c$" "b.C" == some [some ".C"]
#guard searchStr "^$" "" == some [some ""]
#guard (searchStr "." "").isNone
#guard searchStr "^(\\w+)@(\\w+)$" "user@example" == some [some "user@example", some "user", some "example"]
#guard searchStr "a{2,3}" "aaaa" == some [some "aaa"]
#guard searchStr "a+?" "aaa" == some [some "a"]
#guard (searchStr "[^a-c]x" "dx").isSome
#guard (searchStr "[a-c]x" "dx").isNone
#guard (searchStr "\\bfoo\\b" "a foo b").isSome
#guard (searchStr "\\bfoo\\b" "afoob").isNone
#guard searchStr "(a)|(b)" "b" == some [some "b", none, some "b"]
#guard searchStr "x*" "yyy" == some [some ""]
#guard (searchStr "^v" "v1").isSome
#guard (searchStr "(?i)^x-test$" "X-Test").isSome
#guard searchStr "(?P<n>ab)c" "zabc" == some [some "abc", some "ab"]

#guard searchStr "(?i:abc)D" "ABCD" == some [some "ABCD"]
#guard (searchStr "(?i:abc)d" "ABCD").isNone
#guard (searchStr "a(?i)b" "aB").isSome
#guard (searchStr "(?i:(sleep\\((\\s*?)(\\d*?)(\\s*?)\\)|benchmark\\((.*?)\\,(.*?)\\)))" "SELECT pg_sleep(10);").isSome
#guard (searchAt "^b" "ab".toUTF8 1).isNone
#guard (searchAt "b" "ab".toUTF8 1).map (·.toList) == some [some (1, 2)]

-- compile mode (ADR-0027): dot-all by default, anchors at the subject ends unless (?m)
#guard (searchStr "a.b" "a\nb").isSome
#guard (searchStr "a$" "a\n").isNone
#guard (searchStr "(?m)^b" "a\nb").isSome
#guard (searchStr "(?i:x).y" "X\ny").isSome
#guard (searchStr "^b" "a\nb").isNone

-- `\x{hh}` (CRS writes bytes this way); more than one byte is outside the byte-string model
#guard searchStr "a\\x{41}b" "aAb" == some [some "aAb"]
#guard (searchStr "[\\x{80}-\\x{bf}]" "\u00a0").isSome
#guard (Regex.compile "\\x{e3}\\x80\\x82") matches .ok _
#guard (Regex.compile "\\x{100}") matches .error _

-- `\A` and `\z` anchor to the subject ends whatever the multiline flag
#guard (searchStr "a\\z" "a\n").isNone
#guard (searchStr "(?m)a\\z" "a\nb").isNone
#guard (searchStr "(?m)a$" "a\nb").isSome
#guard (searchStr "\\Aa" "ba").isNone
#guard (searchStr "(?m)\\Ab" "a\nb").isNone
#guard searchStr "\\Aab\\z" "ab" == some [some "ab"]
#guard (Regex.compile "a\\Z") matches .error _

end SecLang.Regex
