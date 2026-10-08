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
  deriving Repr

structure Flags where
  ci : Bool := false
  dotAll : Bool := false
  multi : Bool := false
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

/-- Parser state: remaining pattern and the next capture index. -/
structure P where
  rest : List Char
  next : Nat := 1

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

/-- A `[...]` class after the opening bracket (and `^`). -/
partial def parseClass (cs : List Char) (acc : List ClassItem) (first : Bool) : Except String (List ClassItem × List Char) :=
  match cs with
  | [] => .error "unterminated class"
  | ']' :: rest => if first then parseClass rest (.ch ']' :: acc) false else .ok (acc.reverse, rest)
  | '\\' :: c :: rest =>
    match escapeItem c with
    | some it => parseClass rest (it :: acc) false
    | none => parseClass rest (.ch (escapeChar c) :: acc) false
  | a :: '-' :: b :: rest =>
    if b == ']' then parseClass ('-' :: b :: rest) (.ch a :: acc) false
    else parseClass rest (.range a b :: acc) false
  | c :: rest => parseClass rest (.ch c :: acc) false

mutual
partial def parseAlt (p : P) : Except String (Re × P) := do
  let (rs, p) ← parseSeq p
  match p.rest with
  | '|' :: rest =>
    let (r2, p2) ← parseAlt { p with rest }
    return (.alt (.seq rs) r2, p2)
  | _ => return (.seq rs, p)

partial def parseSeq (p : P) : Except String (List Re × P) := do
  match p.rest with
  | [] | ')' :: _ | '|' :: _ => return ([], p)
  | _ =>
    let (a, p) ← parseQuantified p
    let (rs, p) ← parseSeq p
    return (a :: rs, p)

partial def parseQuantified (p : P) : Except String (Re × P) := do
  let (a, p) ← parseAtom p
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

partial def parseAtom (p : P) : Except String (Re × P) := do
  match p.rest with
  | '(' :: '?' :: ':' :: rest => parseGroup none { p with rest }
  | '(' :: '?' :: 'P' :: '<' :: rest =>
    let rest := (rest.dropWhile (· != '>')).drop 1
    parseGroup (some p.next) { rest, next := p.next + 1 }
  | '(' :: '?' :: _ => .error "group syntax outside the Core subset"
  | '(' :: rest => parseGroup (some p.next) { rest, next := p.next + 1 }
  | '[' :: '^' :: rest =>
    let (items, rest) ← parseClass rest [] true
    return (.cls true items, { p with rest })
  | '[' :: rest =>
    let (items, rest) ← parseClass rest [] true
    return (.cls false items, { p with rest })
  | '.' :: rest => return (.any, { p with rest })
  | '^' :: rest => return (.bol, { p with rest })
  | '$' :: rest => return (.eol, { p with rest })
  | '\\' :: 'b' :: rest => return (.wordB false, { p with rest })
  | '\\' :: 'B' :: rest => return (.wordB true, { p with rest })
  | '\\' :: 'x' :: a :: b :: rest =>
    match hexChar a b with
    | some c => return (.lit c, { p with rest })
    | none => .error "bad \\x escape"
  | '\\' :: c :: rest =>
    match escapeItem c with
    | some it => return (.cls false [it], { p with rest })
    | none => return (.lit (escapeChar c), { p with rest })
  | '\\' :: [] => .error "trailing backslash"
  | c :: rest =>
    if c == '*' || c == '+' || c == '?' then .error "nothing to repeat" else return (.lit c, { p with rest })
  | [] => .error "unexpected end of pattern"

partial def parseGroup (cap : Option Nat) (p : P) : Except String (Re × P) := do
  let (r, p) ← parseAlt p
  match p.rest with
  | ')' :: rest => return (.group cap r, { p with rest })
  | _ => .error "missing )"
end

/-- Leading `(?flags)` groups. -/
partial def leadingFlags (cs : List Char) (f : Flags) : List Char × Flags :=
  match cs with
  | '(' :: '?' :: rest =>
    let letters := rest.takeWhile fun c => c == 'i' || c == 's' || c == 'm'
    match rest.drop letters.length with
    | ')' :: rest' =>
      if letters.isEmpty then (cs, f)
      else leadingFlags rest' { ci := f.ci || letters.contains 'i', dotAll := f.dotAll || letters.contains 's', multi := f.multi || letters.contains 'm' }
    | _ => (cs, f)
  | _ => (cs, f)

/-- Flags, tree and group count of a pattern. -/
def compile (pat : String) : Except String (Flags × Re × Nat) := do
  let (cs, f) := leadingFlags pat.toList {}
  let (r, p) ← parseAlt { rest := cs }
  if !p.rest.isEmpty then throw "unbalanced )"
  return (f, r, p.next - 1)

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

mutual
/-- Match `r` at `i`, then continue with `k`. -/
partial def m (f : Flags) (s : Array Char) (r : Re) (i : Nat) (caps : Caps) (k : Nat → Caps → Option Caps) : Option Caps :=
  match r with
  | .lit c => if h : i < s.size then (if eqc f s[i] c then k (i + 1) caps else none) else none
  | .any => if h : i < s.size then (if s[i] == '\n' && !f.dotAll then none else k (i + 1) caps) else none
  | .cls neg items => if h : i < s.size then (if classMatch f neg items s[i] then k (i + 1) caps else none) else none
  | .bol => if i == 0 || (f.multi && s[i - 1]! == '\n') then k i caps else none
  | .eol => if i == s.size || (i + 1 == s.size && s[i]! == '\n') || (f.multi && i < s.size && s[i]! == '\n') then k i caps else none
  | .wordB neg =>
    let before := i > 0 && isWordC s[i - 1]!
    let after := i < s.size && isWordC s[i]!
    if (before != after) != neg then k i caps else none
  | .group cap r => m f s r i caps fun j caps' => k j (match cap with | some n => caps'.setIfInBounds n (some (i, j)) | none => caps')
  | .alt a b => match m f s a i caps k with | some c => some c | none => m f s b i caps k
  | .seq [] => k i caps
  | .seq (r :: rs) => m f s r i caps fun j c => m f s (.seq rs) j c k
  | .rep r mn mx greedy => repM f s r mn mx greedy i caps k 0

partial def repM (f : Flags) (s : Array Char) (r : Re) (mn : Nat) (mx : Option Nat) (greedy : Bool)
    (i : Nat) (caps : Caps) (k : Nat → Caps → Option Caps) (count : Nat) : Option Caps :=
  let canMore : Bool := match mx with | some x => decide (count < x) | none => true
  let more := fun (_ : Unit) => if canMore then
      m f s r i caps (fun j c => if j == i && decide (count ≥ mn) then none else repM f s r mn mx greedy j c k (count + 1))
    else none
  let stop := fun (_ : Unit) => if count ≥ mn then k i caps else none
  if greedy then (match more () with | some c => some c | none => stop ())
  else (match stop () with | some c => some c | none => more ())
end

/-- Leftmost match of `pat` anywhere in `subject`; groups as byte slices, `none` for a group
that did not take part or for a pattern outside the subset. -/
def search (pat : String) (subject : ByteArray) : Option (Array (Option ByteArray)) :=
  match compile pat with
  | .error _ => none
  | .ok (f, r, n) =>
    let s : Array Char := subject.data.map fun b => Char.ofNat b.toNat
    let rec tryFrom (i : Nat) (fuel : Nat) : Option Caps :=
      match fuel with
      | 0 => none
      | fuel + 1 =>
        match m f s r i (Array.replicate (n + 1) none) (fun j caps => some (caps.setIfInBounds 0 (some (i, j)))) with
        | some caps => some caps
        | none => if i < s.size then tryFrom (i + 1) fuel else none
    (tryFrom 0 (s.size + 1)).map fun caps => caps.map fun
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

end SecLang.Regex
