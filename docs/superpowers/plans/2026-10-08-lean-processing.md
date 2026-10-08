# Lean Stage 3: Processing Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An executable semantics of spec 03 over the stage 2 AST, checked by `lake exe seclang-eval` against every engine profile the abstract transaction can carry, with three theorems (ADR-0017, ADR-0016, interruption) proved.

**Architecture:** `Regex.lean` is a backtracking matcher for the Core `@rx` subset and the oracle's implementation. `Request.lean` builds the variable store from a request and response (chapters 05 and 09, URL-encoded only). `Semantics.lean` folds the `Config` into effective chains and markers (exceptions, default actions), evaluates rules (selection, transformations, operators, macros, `setvar`, `ctl`, `capture`), runs the five phases with local skip state, and states the theorems. `EvalMain.lean` reads the extended extractor JSON and compares the four assertion kinds, reporting unsupported profiles with a reason.

**Tech Stack:** Lean `v4.34.1` (`export PATH="$HOME/.elan/bin:$PATH"`), Lake 5; Python via `uv`.

**Spec:** `docs/superpowers/specs/2026-10-08-lean-processing-design.md`; normative text `spec/03-processing-model.md`, plus `05`, `06`, `08`, `09` where it points.

## Global Constraints

- The semantics is parametric in `Oracle` (regex) and `prepare` (store per phase); no IO in `Semantics.lean`.
- `runItems`, `step` and `runTransaction` are total (structural recursion), so the theorems can unfold them; `partial` is allowed only in the regex matcher and in the macro scanner.
- Values are byte strings; config text becomes bytes with `String.toUTF8`, store keys compared case-insensitively on their Latin-1 form (`ofBytes`, moved to `Bytes.lean`).
- "Not specified" points get one documented choice (design §1); no guard or profile depends on them.
- Guards first, watched failing. Every commit passes `cd formal && lake build`; from Task 5 on also `lake exe seclang-eval .lake/engine-rules.json`; validator 0 errors; tools tests; the Coraza adapter is rerun when a profile changes.
- Commit messages end with the two attribution lines. Never push.

## Review Focus

1. A negated operator on a variable that selects nothing (`!@streq x` on an absent argument). Expected: the rule does not match (`06#unconditionalmatch`), guard in Task 3.
2. `skipAfter` naming a rule id rather than a marker. Expected: evaluation resumes after that rule; guard in Task 3.
3. `allow:request` in phase 1 with phase 3 and 5 rules. Expected: phases 3 and 5 run, phase 2 does not; guard in Task 3.
4. `ctl:ruleEngine=Off` in phase 1 followed by another phase-1 rule. Expected: the phase-1 rule still runs (model choice), phase 2 does not; guard in Task 3.
5. `SecArgumentsLimit` across GET and POST arguments. Expected: the cap counts both; guard in Task 2.

---

### Task 1: Regex matcher

**Files:**
- Create: `formal/SecLang/Regex.lean`
- Modify: `formal/SecLang.lean` (import), `formal/SecLang/Bytes.lean` (`ofBytes`, `toBytes` moved here from `Main.lean`; `Main.lean` keeps using them)

**Interfaces:**
- Produces: `SecLang.Regex.search : String → ByteArray → Option (Array (Option ByteArray))` (group 0 is the whole match; `none` when the pattern does not match; a malformed pattern never matches), `SecLang.Regex.searchStr : String → String → Option (List (Option String))` (guard helper).

- [ ] **Step 1: Guards (RED)** — create the file with the header and only:

```lean
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
```

`lake build` → unknown identifier.

- [ ] **Step 2: Matcher**

```lean
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
  let x ← hexVal a.toNat.toUInt8
  let y ← hexVal b.toNat.toUInt8
  if a.isAlphanum && b.isAlphanum then some (Char.ofNat (x.toNat * 16 + y.toNat)) else none

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

/-- A `[...]` class after the opening bracket. -/
partial def parseClass (cs : List Char) (acc : List ClassItem) (first : Bool) : Except String (List ClassItem × List Char) :=
  match cs with
  | [] => .error "unterminated class"
  | ']' :: rest => if first then parseClass rest (.ch ']' :: acc) false else .ok (acc.reverse, rest)
  | '\\' :: c :: rest =>
    match escapeItem c with
    | some it => parseClass rest (it :: acc) false
    | none => parseClass rest (.ch (escapeChar c) :: acc) false
  | a :: '-' :: b :: rest => if b == ']' then parseClass ('-' :: b :: rest) (.ch a :: acc) false
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
  | '[' :: '^' :: rest => let (items, rest) ← parseClass rest [] true; return (.cls true items, { p with rest })
  | '[' :: rest => let (items, rest) ← parseClass rest [] true; return (.cls false items, { p with rest })
  | '.' :: rest => return (.any, { p with rest })
  | '^' :: rest => return (.bol, { p with rest })
  | '$' :: rest => return (.eol, { p with rest })
  | '\\' :: 'b' :: rest => return (.wordB false, { p with rest })
  | '\\' :: 'B' :: rest => return (.wordB true, { p with rest })
  | '\\' :: 'x' :: a :: b :: rest =>
    match hexChar a b with | some c => return (.lit c, { p with rest }) | none => .error "bad \\x escape"
  | '\\' :: c :: rest =>
    match escapeItem c with
    | some it => return (.cls false [it], { p with rest })
    | none => return (.lit (escapeChar c), { p with rest })
  | '\\' :: [] => .error "trailing backslash"
  | c :: rest => if c == '*' || c == '+' || c == '?' then .error "nothing to repeat" else return (.lit c, { p with rest })
  | [] => .error "unexpected end of pattern"

partial def parseGroup (cap : Option Nat) (p : P) : Except String (Re × P) := do
  let (r, p) ← parseAlt p
  match p.rest with
  | ')' :: rest => return (.group cap r, { p with rest })
  | _ => .error "missing )"
end

/-- Leading `(?flags)` groups, then the pattern; returns flags, tree and group count. -/
def compile (pat : String) : Except String (Flags × Re × Nat) := do
  let rec flags (cs : List Char) (f : Flags) : List Char × Flags :=
    match cs with
    | '(' :: '?' :: rest =>
      let letters := rest.takeWhile fun c => c == 'i' || c == 's' || c == 'm'
      match rest.drop letters.length with
      | ')' :: rest' => if letters.isEmpty then (cs, f) else
          flags rest' { ci := f.ci || letters.contains 'i', dotAll := f.dotAll || letters.contains 's', multi := f.multi || letters.contains 'm' }
      | _ => (cs, f)
    | _ => (cs, f)
  let (cs, f) := flags pat.toList {}
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
  | .eol => if i == s.size || (i + 1 == s.size && s[i]! == '\n') || (f.multi && s[i]! == '\n') then k i caps else none
  | .wordB neg =>
    let before := i > 0 && isWordC s[i - 1]!
    let after := i < s.size && isWordC s[i]!
    if (before != after) != neg then k i caps else none
  | .group cap r => m f s r i caps fun j caps' => k j (match cap with | some n => caps'.setD n (some (i, j)) | none => caps')
  | .alt a b => match m f s a i caps k with | some c => some c | none => m f s b i caps k
  | .seq [] => k i caps
  | .seq (r :: rs) => m f s r i caps fun j c => m f s (.seq rs) j c k
  | .rep r mn mx greedy => repM f s r mn mx greedy i caps k 0

partial def repM (f : Flags) (s : Array Char) (r : Re) (mn : Nat) (mx : Option Nat) (greedy : Bool)
    (i : Nat) (caps : Caps) (k : Nat → Caps → Option Caps) (count : Nat) : Option Caps :=
  let canMore := match mx with | some x => count < x | none => true
  let more := fun (_ : Unit) => if canMore then
      m f s r i caps (fun j c => if j == i && count ≥ mn then none else repM f s r mn mx greedy j c k (count + 1))
    else none
  let stop := fun (_ : Unit) => if count ≥ mn then k i caps else none
  if greedy then (match more () with | some c => some c | none => stop ())
  else (match stop () with | some c => some c | none => more ())
end

/-- Leftmost match of `pat` anywhere in `subject`; groups as byte slices. -/
def search (pat : String) (subject : ByteArray) : Option (Array (Option ByteArray)) :=
  match compile pat with
  | .error _ => none
  | .ok (f, r, n) =>
    let s : Array Char := subject.data.map fun b => Char.ofNat b.toNat
    let rec tryFrom (i : Nat) (fuel : Nat) : Option Caps :=
      match fuel with
      | 0 => none
      | fuel + 1 =>
        match m f s r i (Array.replicate (n + 1) none) (fun j caps => some (caps.setD 0 (some (i, j)))) with
        | some caps => some caps
        | none => if i < s.size then tryFrom (i + 1) fuel else none
    (tryFrom 0 (s.size + 1)).map fun caps => caps.map fun
      | some (a, b) => some (subject.extract a b)
      | none => none

/-- Guard helper: pattern and subject as strings. -/
def searchStr (pat subject : String) : Option (List (Option String)) :=
  (search pat subject.toUTF8).map fun caps => caps.toList.map (·.map ofBytes)

end SecLang.Regex
```

Move `ofBytes`/`toBytes` from `Main.lean` into `Bytes.lean` (namespace `SecLang`; `Main.lean` opens `SecLang` already). `lake build` → success.

- [ ] **Step 3: Commit** — `feat(formal): regex matcher for the Core @rx subset`.

---

### Task 2: Store population and the extended extractor

**Files:**
- Create: `formal/SecLang/Request.lean`
- Modify: `formal/SecLang.lean`, `tools/engine_rules.py`, `tools/test_engine_rules.py`

**Interfaces:**
- Produces: `SecLang.Member` (`key : String`, `value : ByteArray`), `SecLang.Store` (`List (String × List Member)`) with `Store.get`/`Store.set`, `scalar`, `text`, `latin`, `Request`, `Response`, `Settings`, `parseArgs : Char → Option Nat → String → List Member`, `phase1Store`, `phase2Store`, `phase3Store`, `phase4Store`, `selectProcessor`, `headerValue`.

- [ ] **Step 1: Guards (RED)**

```lean
#guard (parseArgs '&' none "a=1&a=2&b=3").map (fun m => (m.key, ofBytes m.value)) == [("a", "1"), ("a", "2"), ("b", "3")]
#guard (parseArgs '&' none "a=1&b&c=x+y%20z&d=%zz").map (fun m => (m.key, ofBytes m.value)) == [("a", "1"), ("b", ""), ("c", "x y z"), ("d", "%zz")]
#guard (parseArgs ';' none "a=1;b=2").map (·.key) == ["a", "b"]
#guard (parseArgs '&' (some 2) "a=1&b=2&c=3").map (·.key) == ["a", "b"]
#guard ((phase1Store {} { uri := "/dir/file.php?x=1" }).get "REQUEST_FILENAME").map (ofBytes ·.value) == ["/dir/file.php"]
#guard ((phase1Store {} { uri := "/dir/file.php?x=1" }).get "REQUEST_BASENAME").map (ofBytes ·.value) == ["file.php"]
#guard ((phase1Store {} { uri := "/dir/file.php?x=1" }).get "QUERY_STRING").map (ofBytes ·.value) == ["x=1"]
#guard ((phase1Store {} { uri := "/", headers := [("Cookie", "a=1; b=2; a=3")] }).get "REQUEST_COOKIES").map (fun m => (m.key, ofBytes m.value)) == [("a", "1"), ("b", "2"), ("a", "3")]
#guard ((phase1Store {} { uri := "/", headers := [("X-Test", " Hello ")] }).get "REQUEST_HEADERS_NAMES").map (ofBytes ·.value) == ["X-Test"]
#guard (let s := phase1Store { argsLimit := some 2 } { uri := "/?a=1&b=2" }
        let s := phase2Store { argsLimit := some 2, requestBodyAccess := true } { method := "POST", uri := "/?a=1&b=2", headers := [("Content-Type", "application/x-www-form-urlencoded")], body := some "p=1" } true none false s
        (s.get "ARGS").length) == 2
#guard (let s := phase2Store { requestBodyAccess := true } { uri := "/", headers := [("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")], body := some "p=1&q=2" } true none false (phase1Store {} { uri := "/" })
        ((s.get "REQBODY_PROCESSOR").map (ofBytes ·.value), (s.get "ARGS_POST").length, (s.get "REQUEST_BODY").map (ofBytes ·.value), (s.get "REQUEST_BODY_LENGTH").map (ofBytes ·.value))) == (["URLENCODED"], 2, ["p=1&q=2"], ["7"])
#guard (let s := phase2Store {} { uri := "/", headers := [("Content-Type", "text/plain")], body := some "a=1" } true none true (phase1Store {} { uri := "/" })
        ((s.get "REQUEST_BODY").map (ofBytes ·.value), (s.get "ARGS_POST").length)) == (["a=1"], 0)
#guard (let s := phase2Store {} { uri := "/", headers := [("Content-Type", "text/plain")], body := some "a=1" } true none false (phase1Store {} { uri := "/" })
        (s.get "REQUEST_BODY").length) == 0
#guard ((phase4Store { responseBodyAccess := true, mimeTypes := ["text/plain"] } (some { headers := [("Content-Type", "text/plain; charset=utf-8")], body := "leak" }) []).get "RESPONSE_BODY").map (ofBytes ·.value) == ["leak"]
#guard ((phase4Store { responseBodyAccess := true, mimeTypes := ["text/plain"] } (some { headers := [("Content-Type", "application/json")], body := "leak" }) []).get "RESPONSE_BODY").length == 0
```

- [ ] **Step 2: Request.lean**

```lean
import SecLang.Syntax
import SecLang.Transformations
/-! The variable store of one transaction, populated from the request and response per
`spec/05-variables.md` and `spec/09-body-processors.md` (URL-encoded bodies only). -/
namespace SecLang

structure Member where
  key : String
  value : ByteArray
  deriving Repr

/-- Canonical collection name → members; a scalar is one member with the empty key. -/
abbrev Store := List (String × List Member)

def Store.get (st : Store) (coll : String) : List Member := (st.lookup coll).getD []
def Store.set (st : Store) (coll : String) (ms : List Member) : Store := (coll, ms) :: st.filter (·.1 != coll)

def text (s : String) : ByteArray := s.toUTF8
/-- A configuration string in the store's key convention (Latin-1 form of its bytes). -/
def latin (s : String) : String := ofBytes s.toUTF8
def scalar (v : ByteArray) : List Member := [⟨"", v⟩]

structure Request where
  method : String := "GET"
  uri : String := "/"
  version : String := "HTTP/1.1"
  headers : List (String × String) := []
  body : Option String := none
  remoteAddr : String := "127.0.0.1"

structure Response where
  status : Nat := 200
  headers : List (String × String) := []
  body : String := ""

/-- Configuration-level settings the store depends on (`04`). The response MIME set has no
specified default (`04#secresponsebodymimetype`): none until set. -/
structure Settings where
  argSep : Char := '&'
  argsLimit : Option Nat := none
  requestBodyAccess : Bool := false
  responseBodyAccess : Bool := false
  mimeTypes : List String := []

def headerValue (hs : List (String × String)) (name : String) : Option String :=
  (hs.find? fun (k, _) => k.toLower == name.toLower).map (·.2)

def limitArgs (lim : Option Nat) (ms : List Member) : List Member :=
  match lim with | some n => ms.take n | none => ms

/-- `name=value` pairs split on `sep`, both sides URL-decoded (`05#args`), capped by
`SecArgumentsLimit`. -/
def parseArgs (sep : Char) (lim : Option Nat) (s : String) : List Member :=
  if s.isEmpty then [] else
  limitArgs lim <| (s.splitOn (String.singleton sep)).map fun pair =>
    let (n, v) := match pair.splitOn "=" with
      | [n] => (n, "") | n :: rest => (n, "=".intercalate rest) | [] => ("", "")
    ⟨ofBytes (urlDecode (text n)), urlDecode (text v)⟩

def namesOf (ms : List Member) : List Member := ms.map fun m => ⟨m.key, text m.key⟩
def combinedSize (ms : List Member) : Nat := ms.foldl (fun n m => n + (text m.key).size + m.value.size) 0
def natText (n : Nat) : List Member := scalar (text (toString n))

/-- Phase 1 store (`05`): request line, headers, cookies, query arguments. -/
def phase1Store (st : Settings) (r : Request) : Store :=
  let (path, query) := match r.uri.splitOn "?" with
    | [p] => (p, "") | p :: rest => (p, "?".intercalate rest) | [] => ("", "")
  let base := (path.splitOn "/").getLast?.getD path
  let getArgs := parseArgs st.argSep st.argsLimit query
  let headers := r.headers.map fun (k, v) => Member.mk k (text (trimBlanks v))
  let cookies := (r.headers.filter fun (k, _) => k.toLower == "cookie").flatMap fun (_, v) =>
    (v.splitOn ";").filterMap fun c =>
      let c := trimBlanks c
      if c.isEmpty then none else some (match c.splitOn "=" with
        | [n] => Member.mk (trimBlanks n) (text "")
        | n :: rest => Member.mk (trimBlanks n) (text (trimBlanks ("=".intercalate rest)))
        | [] => Member.mk "" (text ""))
  [("REQUEST_METHOD", scalar (text r.method)), ("REQUEST_URI", scalar (text r.uri)),
   ("REQUEST_URI_RAW", scalar (text r.uri)), ("REQUEST_FILENAME", scalar (text path)),
   ("REQUEST_BASENAME", scalar (text base)), ("QUERY_STRING", scalar (text query)),
   ("REQUEST_PROTOCOL", scalar (text r.version)),
   ("REQUEST_LINE", scalar (text s!"{r.method} {r.uri} {r.version}")),
   ("REMOTE_ADDR", scalar (text r.remoteAddr)), ("UNIQUE_ID", scalar (text "seclang-model")),
   ("REQUEST_HEADERS", headers), ("REQUEST_HEADERS_NAMES", namesOf headers),
   ("REQUEST_COOKIES", cookies), ("REQUEST_COOKIES_NAMES", namesOf cookies),
   ("ARGS_GET", getArgs), ("ARGS_GET_NAMES", namesOf getArgs), ("ARGS", getArgs),
   ("ARGS_NAMES", namesOf getArgs), ("ARGS_COMBINED_SIZE", natText (combinedSize getArgs)),
   ("REQUEST_BODY_LENGTH", natText 0), ("REQBODY_PROCESSOR", scalar (text ""))]

/-- Body processor from the `Content-Type` prefix (`09#processor-selection`) unless a
phase 1 `ctl:requestBodyProcessor` chose one. -/
def selectProcessor (override : Option String) (contentType : Option String) : String :=
  match override with
  | some p => p.toUpper
  | none => match contentType with
    | some ct =>
      if ct.toLower.startsWith "application/x-www-form-urlencoded" then "URLENCODED"
      else if ct.toLower.startsWith "multipart/form-data" then "MULTIPART" else ""
    | none => ""

/-- Phase 2 additions when the body is read (`09#urlencoded`, `05#request_body`, ADR-0022):
`access` and `processor` come from the settings as overridden by phase 1 `ctl`s. -/
def phase2Store (st : Settings) (r : Request) (access : Bool) (processor : Option String) (force : Bool) (store : Store) : Store :=
  match r.body with
  | none => store
  | some body =>
    if !access then store else
    let proc := selectProcessor processor (headerValue r.headers "Content-Type")
    let get := store.get "ARGS_GET"
    let post := if proc == "URLENCODED" then parseArgs st.argSep none body else []
    let all := limitArgs st.argsLimit (get ++ post)
    let post := all.drop get.length
    let reqBody := if proc == "URLENCODED" || force then scalar (text body) else []
    store |>.set "ARGS_POST" post |>.set "ARGS_POST_NAMES" (namesOf post)
      |>.set "ARGS" all |>.set "ARGS_NAMES" (namesOf all)
      |>.set "ARGS_COMBINED_SIZE" (natText (combinedSize all))
      |>.set "REQUEST_BODY" reqBody |>.set "REQUEST_BODY_LENGTH" (natText (text body).size)
      |>.set "REQBODY_PROCESSOR" (scalar (text proc))

/-- Phase 3 additions (`05#response_status`, `05#response_headers`). -/
def phase3Store (resp : Option Response) (store : Store) : Store :=
  match resp with
  | none => store
  | some rs =>
    let hs := rs.headers.map fun (k, v) => Member.mk k (text (trimBlanks v))
    store |>.set "RESPONSE_STATUS" (natText rs.status) |>.set "RESPONSE_HEADERS" hs

/-- Phase 4 additions (`05#response_body`, `04#secresponsebodyaccess`): the body when access
is on and the MIME type (parameters stripped) is listed. -/
def phase4Store (st : Settings) (resp : Option Response) (store : Store) : Store :=
  match resp with
  | none => store
  | some rs =>
    let ct := (headerValue rs.headers "Content-Type").map fun c => trimBlanks ((c.splitOn ";").headD "")
    if st.responseBodyAccess && ct.any st.mimeTypes.contains then store.set "RESPONSE_BODY" (scalar (text rs.body)) else store

end SecLang
```

- [ ] **Step 3: Extractor** — `tools/engine_rules.py` adds `"tests": d["tests"]` to each record; `tools/test_engine_rules.py` asserts `out[0]["tests"][0]["stages"][0]["stage"]["output"]["expect_error"] is True`. RED → GREEN. Regenerate `formal/.lake/engine-rules.json`; `lake exe seclang-parse .lake/engine-rules.json` still reports 0 mismatches.
- [ ] **Step 4: Commit** — `feat(formal): transaction store from request and response; extractor emits stages`.

---

### Task 3: Semantics

**Files:**
- Create: `formal/SecLang/Semantics.lean`
- Modify: `formal/SecLang.lean`, `formal/SecLang/Transformations.lean` (`byName` table), `formal/Main.lean` (uses `byName`)

**Interfaces:**
- Produces: `Oracle`, `Mode`, `Interruption`, `AllowScope`, `Chain`, `Item`, `effectiveItems : Oracle → Config → List Item`, `Tx`, `runItems`, `step`, `runTransaction : Oracle → List Item → (Nat → Tx → Store) → Tx → Tx`, `chainPhase`, `phaseRuns`, `startPhase`, `PhaseState`.

- [ ] **Step 1: Guards (RED)** — with a test oracle `testOracle : Oracle := ⟨Regex.search⟩`, a helper `run (cfg : String) (store : Store) : Tx` that parses, builds items with `settingsOf`-free defaults (mode `on`), and runs with `prepare := fun _ tx => if tx.store.isEmpty then store else tx.store`, and `tri (tx) := tx.triggered`:

```lean
def demoStore (args : List (String × String)) : Store :=
  [("ARGS_GET", args.map fun (k, v) => ⟨k, text v⟩), ("ARGS", args.map fun (k, v) => ⟨k, text v⟩), ("REQUEST_HEADERS", [⟨"X-P", text "1"⟩])]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 2\" \"id:2,phase:1,pass\"" (demoStore [("a", "1")])) == [1]
-- skip, skipAfter to a marker, skipAfter to a rule id, missing marker ends with the phase
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,skip:1\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:1,pass,skipAfter:END\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:4,phase:1,pass\"\nSecMarker END\nSecRule ARGS_GET:a \"@streq 1\" \"id:5,phase:1,pass\"" (demoStore [("a", "1")])) == [1, 3, 5]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,skipAfter:3\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:4,phase:1,pass\"" (demoStore [("a", "1")])) == [1, 4]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,skipAfter:NOWHERE\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:2,pass\"" (demoStore [("a", "1")])) == [1, 3]
-- chains, negation on no values, default actions, block, interruption, allow:request, ctl timing
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,chain\"\n  SecRule ARGS_GET:b \"@streq 2\" \"t:none\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass,chain\"\n  SecRule ARGS_GET:b \"@streq 3\"" (demoStore [("a", "1"), ("b", "2")])) == [1]
#guard tri (run "SecRule ARGS_GET:zz \"!@streq x\" \"id:1,phase:1,pass\"" (demoStore [("a", "1")])) == []
#guard tri (run "SecRule ARGS_GET:a \"!@streq x\" \"id:1,phase:1,pass\"" (demoStore [("a", "1")])) == [1]
#guard (run "SecDefaultAction \"phase:1,log,deny,status:418\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1\"" (demoStore [("a", "1")])).interruption == some ⟨1, "deny", 418⟩
#guard (run "SecDefaultAction \"phase:1,log,deny,status:418\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,status:403\"" (demoStore [("a", "1")])).interruption == some ⟨1, "deny", 403⟩
#guard (run "SecDefaultAction \"phase:1,log,deny,status:418\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass\"" (demoStore [("a", "1")])).interruption == none
#guard (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,block\"" (demoStore [("a", "1")])).interruption == none
#guard (run "SecDefaultAction \"phase:1,log,deny,status:403\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,block\"" (demoStore [("a", "1")])).interruption == some ⟨1, "deny", 403⟩
#guard (let tx := run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,deny,status:401\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,deny\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:2,deny\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:4,phase:5,pass\"" (demoStore [("a", "1")])
        (tx.triggered, tx.interruption)) == ([1, 4], some ⟨1, "deny", 401⟩)
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,allow:request\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:2,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:4,phase:3,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:5,phase:5,pass\"" (demoStore [("a", "1")])) == [1, 4, 5]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,nolog,ctl:ruleEngine=Off\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:2,pass\"" (demoStore [("a", "1")])) == [1, 2]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,nolog,ctl:ruleRemoveById=2\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"" (demoStore [("a", "1")])) == [1]
-- setvar, macros, capture, t:, multiMatch, exceptions, retargeting, count and exclusion
#guard tri (run "SecAction \"id:1,phase:1,pass,nolog,setvar:tx.a=5,setvar:tx.a=+3,setvar:tx.b=%{tx.a},setvar:tx.c=x,setvar:!tx.c,setvar:tx.d\"\nSecRule TX:a \"@eq 8\" \"id:2,phase:1,pass\"\nSecRule TX:b \"@streq 8\" \"id:3,phase:1,pass\"\nSecRule &TX:c \"@eq 0\" \"id:4,phase:1,pass\"\nSecRule TX:d \"@eq 1\" \"id:5,phase:1,pass\"" (demoStore [])) == [1, 2, 3, 4, 5]
#guard tri (run "SecRule ARGS_GET:a \"@rx ^(\\w+)-(\\w+)$\" \"id:1,phase:1,pass,capture,setvar:tx.first=%{TX.1}\"\nSecRule TX:first \"@streq foo\" \"id:2,phase:1,pass\"\nSecRule TX:0 \"@streq foo-bar\" \"id:3,phase:1,pass\"\nSecRule TX:2 \"@streq bar\" \"id:4,phase:1,pass\"" (demoStore [("a", "foo-bar")])) == [1, 2, 3, 4]
#guard tri (run "SecRule ARGS_GET:a \"@streq abc\" \"id:1,phase:1,pass,t:lowercase,t:hexEncode,multiMatch\"\nSecRule ARGS_GET:a \"@streq abc\" \"id:2,phase:1,pass,t:lowercase,t:hexEncode\"\nSecRule ARGS_GET:a \"@streq ABC\" \"id:3,phase:1,pass,t:lowercase,t:none\"" (demoStore [("a", "ABC")])) == [1, 3]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,tag:'drop-me'\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a|ARGS_GET:b \"@streq 1\" \"id:3,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:4,phase:1,deny\"\nSecRuleRemoveByTag drop-me\nSecRuleRemoveById 2\nSecRuleUpdateTargetById 3 \"!ARGS_GET:a\"\nSecRuleUpdateActionById 4 \"pass\"" (demoStore [("a", "1")])) == [4]
#guard tri (run "SecRule &ARGS_GET \"@eq 2\" \"id:1,phase:1,pass\"\nSecRule ARGS_GET|!ARGS_GET:skip \"@streq x\" \"id:2,phase:1,pass\"" (demoStore [("skip", "x"), ("b", "2")])) == [1]
#guard tri (run "SecRule ARGS_GET:a \"@streq %{tx.expected}\" \"id:2,phase:1,pass\"\nSecAction \"id:1,phase:1,pass,nolog,setvar:tx.expected=secret\"\nSecRule ARGS_GET:a \"@streq %{TX.EXPECTED}\" \"id:3,phase:1,pass\"" (demoStore [("a", "secret")])) == [1, 3]
-- MATCHED_VAR*, ctl removal of a target, @pm and numerics
#guard tri (run "SecRule ARGS_GET:a \"@streq hello\" \"id:1,phase:1,pass,t:lowercase,chain\"\n  SecRule MATCHED_VAR \"@streq hello\" \"t:none\"\nSecRule ARGS_GET:a \"@streq hello\" \"id:2,phase:1,pass,t:lowercase,chain\"\n  SecRule MATCHED_VAR_NAME \"@streq ARGS_GET:a\" \"t:none\"\nSecRule ARGS_GET:b|ARGS_GET:c \"@rx ^v\" \"id:3,phase:1,pass,chain\"\n  SecRule &MATCHED_VARS \"@eq 2\" \"t:none\"" (demoStore [("a", "HeLLo"), ("b", "v1"), ("c", "v2")])) == [1, 2, 3]
#guard tri (run "SecRule REQUEST_HEADERS:X-P \"@streq 1\" \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=2;ARGS_GET:a\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:1,pass\"" (demoStore [("a", "1")])) == [1, 3]
#guard tri (run "SecRule ARGS_GET:q \"@pm forbidden other\" \"id:1,phase:1,pass\"\nSecRule &ARGS_GET \"@lt 3\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@eq 0\" \"id:3,phase:1,pass\"\nSecRule ARGS_GET:q \"@contains FORB\" \"id:4,phase:1,pass\"" (demoStore [("q", "this is FORBIDDEN"), ("a", "abc")])) == [1, 2, 3, 4]
```

- [ ] **Step 2: Transformations table** — in `Transformations.lean` (end of file) add `def byName : List (String × (ByteArray → ByteArray)) := [...]` with the 35 names (copy the `formalized` list from `Main.lean`, which then becomes `def formalized := byName`). `lake build` still green.

- [ ] **Step 3: Semantics.lean**

```lean
import SecLang.Syntax
import SecLang.Transformations
import SecLang.Request
import SecLang.Regex
/-! The processing model (`spec/03-processing-model.md`): effective rules, one transaction
through five phases, parametric in a regular-expression oracle and in how the store is
populated per phase. -/
namespace SecLang

structure Oracle where
  rx : String → ByteArray → Option (Array (Option ByteArray))

inductive Mode | on | off | detectionOnly
  deriving Repr, BEq, DecidableEq

def modeOf (s : String) : Mode :=
  match s.toLower with | "off" => .off | "detectiononly" => .detectionOnly | _ => .on

structure Interruption where
  ruleId : Nat
  action : String
  status : Nat
  deriving Repr, BEq

inductive AllowScope | phase | request | all
  deriving Repr, BEq, DecidableEq

/-- A chain starter with its members and its effective disruptive action, status and
inherited cumulative actions (`03#chains`, `03#default-actions`). -/
structure Chain where
  id : Nat
  phase : Nat
  starter : Rule
  members : List Rule := []
  disruptive : Option String
  status : Option Nat
  extra : List Action
  deriving Repr

inductive Item
  | chain (c : Chain)
  | marker (label : String)
  deriving Repr

def actionValue (as : List Action) (n : String) : Option String := (as.find? (·.name == n)).bind (·.value)
def isDisruptiveName (n : String) : Bool := (findAction n).any (·.2.2 == .disruptive)
def ownDisruptive (as : List Action) : Option String := (as.find? fun a => isDisruptiveName a.name).map (·.name)
def cumulative (as : List Action) : List Action := as.filter fun a => a.name == "setvar" || a.name == "ctl" || a.name == "tag"

/-- `03#phases`, ADR-0017: the rule's own `phase` or 2; never taken from `SecDefaultAction`. -/
def chainPhase (r : Rule) : Nat := ((actionValue r.actions "phase").bind phaseNumber).getD 2

/-- The chain for a starter, with the default actions of its phase merged in: the rule's own
actions win; `block` takes the inherited disruptive action; cumulative actions are appended. -/
def mkChain (defaults : List (Nat × List Action)) (r : Rule) : Chain :=
  let phase := chainPhase r
  let dflt := (defaults.lookup phase).getD []
  let inherited := match ownDisruptive dflt with | some "block" => none | d => d
  let disruptive := match ownDisruptive r.actions with
    | some "block" => inherited
    | some d => some d
    | none => inherited
  let status := match (actionValue r.actions "status").bind natOf? with
    | some s => some s | none => (actionValue dflt "status").bind natOf?
  { id := ((actionValue r.actions "id").bind natOf?).getD 0, phase, starter := r, disruptive, status, extra := cumulative dflt }

/-- `SecRuleUpdateActionById`: a disruptive action replaces, `status` replaces, cumulative
actions are appended (`03#rule-exceptions`). -/
def updateActions (c : Chain) (acts : List Action) : Chain :=
  let disruptive := match ownDisruptive acts with | some "block" => c.disruptive | some d => some d | none => c.disruptive
  let status := match (actionValue acts "status").bind natOf? with | some s => some s | none => c.status
  { c with disruptive, status, extra := c.extra ++ cumulative acts }

def inRanges (ranges : List (Nat × Nat)) (id : Nat) : Bool := ranges.any fun (a, z) => a ≤ id && id ≤ z
def tagsOf (c : Chain) : List String := (c.starter.actions.filter (·.name == "tag")).filterMap (·.value)
def msgOf (c : Chain) : String := (actionValue c.starter.actions "msg").getD ""
def rxName (o : Oracle) (re s : String) : Bool := (o.rx re (text s)).isSome
def addTargets (c : Chain) (ts : List Variable) : Chain :=
  { c with starter := { c.starter with variables := c.starter.variables ++ ts } }

structure Build where
  items : List Item := []          -- reversed
  cur : Option Chain := none
  defaults : List (Nat × List Action) := []

def Build.flush (b : Build) : Build :=
  match b.cur with | some c => { b with items := .chain c :: b.items, cur := none } | none => b
def Build.mapChains (b : Build) (f : Chain → Chain) : Build :=
  let b := b.flush
  { b with items := b.items.map fun | .chain c => .chain (f c) | i => i }
def Build.filterChains (b : Build) (p : Chain → Bool) : Build :=
  let b := b.flush
  { b with items := b.items.filter fun | .chain c => p c | _ => true }

/-- One directive into the build (`03#rule-exceptions`: each applies to the rules already
defined). -/
def buildStep (o : Oracle) (b : Build) : Directive → Build
  | .rule r =>
    if r.chainMember then
      match b.cur with
      | some c => { b with cur := some { c with members := c.members ++ [r] } }
      | none => b
    else
      let b := b.flush
      { b with cur := some (mkChain b.defaults r) }
  | .defaultAction _ phase acts => let b := b.flush; { b with defaults := (phase, acts) :: b.defaults }
  | .marker _ l => let b := b.flush; { b with items := .marker l :: b.items }
  | .removeById _ rs => b.filterChains fun c => !inRanges rs c.id
  | .removeByTag _ re => b.filterChains fun c => !(tagsOf c).any (rxName o re)
  | .removeByMsg _ re => b.filterChains fun c => !rxName o re (msgOf c)
  | .updateActionById _ rs acts => b.mapChains fun c => if inRanges rs c.id then updateActions c acts else c
  | .updateTargetById _ rs ts => b.mapChains fun c => if inRanges rs c.id then addTargets c ts else c
  | .updateTargetByTag _ re ts => b.mapChains fun c => if (tagsOf c).any (rxName o re) then addTargets c ts else c
  | .updateTargetByMsg _ re ts => b.mapChains fun c => if rxName o re (msgOf c) then addTargets c ts else c
  | .setting .. => b

/-- Effective chains and markers in configuration order. -/
def effectiveItems (o : Oracle) (cfg : Config) : List Item :=
  (cfg.directives.foldl (buildStep o) {}).flush.items.reverse

/-- Transaction state. -/
structure Tx where
  store : Store := []
  tx : List Member := []
  mode : Mode := .on
  nextMode : Mode := .on
  removedIds : List Nat := []
  removedTags : List String := []
  removedTargets : List (Nat × Variable) := []
  removedTagTargets : List (String × Variable) := []
  bodyAccess : Option Bool := none
  bodyProcessor : Option String := none
  forceBody : Bool := false
  interruption : Option Interruption := none
  allow : Option AllowScope := none
  ended : Bool := false
  triggered : List Nat := []
  evaluated : List Nat := []
  matchedVar : ByteArray := .empty
  matchedVarName : String := ""
  matchedVars : List Member := []

def keyEq (a b : String) : Bool := a.toLower == b.toLower

/-- Members of a collection, `TX` and the `MATCHED_*` variables included. -/
def collection (tx : Tx) (name : String) : List Member :=
  match name with
  | "TX" => tx.tx
  | "MATCHED_VAR" => scalar tx.matchedVar
  | "MATCHED_VAR_NAME" => scalar (text tx.matchedVarName)
  | "MATCHED_VARS" => tx.matchedVars
  | _ => tx.store.get name

def fullName (coll : String) (m : Member) : String := if m.key.isEmpty then coll else s!"{coll}:{m.key}"

def selectMembers (o : Oracle) (tx : Tx) (v : Variable) : List Member :=
  let ms := collection tx v.collection
  match v.selector with
  | none => ms
  | some (.key k) => ms.filter fun m => keyEq m.key (latin k)
  | some (.regex re) => ms.filter fun m => rxName o re m.key
  | some (.xpath _) => []

/-- Does the exclusion `v` cover a selected value named `name` (`COLL` or `COLL:key`)? -/
def covers (o : Oracle) (v : Variable) (name : String) : Bool :=
  let (coll, key) := match name.splitOn ":" with
    | [c] => (c, "") | c :: rest => (c, ":".intercalate rest) | [] => ("", "")
  keyEq coll v.collection && match v.selector with
    | none => true
    | some (.key k) => keyEq key (latin k)
    | some (.regex re) => rxName o re key
    | some (.xpath _) => false

/-- The values a variable list selects (`02#variable-list`): union in order, `!` removes,
`&` counts; extra exclusions come from `ctl:ruleRemoveTarget*`. -/
def selectValues (o : Oracle) (tx : Tx) (vars : List Variable) (exclusions : List Variable) : List (String × ByteArray) :=
  let step (acc : List (String × ByteArray)) (v : Variable) : List (String × ByteArray) :=
    if v.negate then acc.filter fun (n, _) => !covers o v n
    else if v.count then acc ++ [(v.collection, text (toString (selectMembers o tx v).length))]
    else acc ++ (selectMembers o tx v).map fun m => (fullName v.collection m, m.value)
  (vars ++ exclusions.map fun e => { e with negate := true }).foldl step []

/-- The `t:` list of a rule; `t:none` resets (`07#none`). -/
def tfnList (as : List Action) : List String :=
  as.foldl (fun acc a => if a.name == "t" then (match a.value with | some "none" => [] | some t => acc ++ [t] | none => acc) else acc) []
def applyTfn (name : String) (v : ByteArray) : ByteArray := match byName.lookup name with | some f => f v | none => v

def macroValue (tx : Tx) (name : String) : ByteArray :=
  let (coll, key) := match name.splitOn "." with
    | [c] => (c, none) | c :: rest => (c, some (".".intercalate rest)) | [] => ("", none)
  let coll := ((findVariable coll).map (·.1)).getD coll.toUpper
  let ms := collection tx coll
  match key with
  | none => ((ms.head?).map (·.value)).getD .empty
  | some k => ((ms.find? fun m => keyEq m.key (latin k)).map (·.value)).getD .empty

/-- `%{NAME}` and `%{COLL.key}` expansion (`02#macro-expansion`); an unset variable is empty. -/
partial def expandMacros (tx : Tx) (s : String) : ByteArray := go s.toList .empty
where
  go : List Char → ByteArray → ByteArray
    | '%' :: '{' :: rest, acc =>
      let name := rest.takeWhile (· != '}')
      go ((rest.dropWhile (· != '}')).drop 1) (acc ++ macroValue tx (String.ofList name))
    | c :: rest, acc => go rest (acc ++ (String.singleton c).toUTF8)
    | [], acc => acc

/-- C `atoi`: optional sign and leading digits, 0 otherwise (`06#eq`). -/
def atoi (b : ByteArray) : Int :=
  let cs := (ofBytes b).toList.dropWhile isBlank
  let (neg, cs) := match cs with | '-' :: r => (true, r) | '+' :: r => (false, r) | _ => (false, cs)
  let n := ((String.ofList (cs.takeWhile Char.isDigit)).toNat?).getD 0
  if neg then -n else n

def containsBytes (hay needle : ByteArray) : Bool :=
  let h := hay.toList; let n := needle.toList
  (List.range (h.length + 1)).any fun i => n.isPrefixOf (h.drop i)

/-- `@pm` phrases: space-separated, `|hex|` runs decoded. -/
def pmPhrases (param : ByteArray) : List ByteArray :=
  ((ofBytes param).splitOn " ").filterMap fun p => if p.isEmpty then none else some (pmDecode p.toList .empty)
where
  pmDecode : List Char → ByteArray → ByteArray
    | '|' :: rest, acc =>
      let hex := rest.takeWhile (· != '|')
      let bytes := hexDecode (String.ofList hex).toUTF8
      pmDecode ((rest.dropWhile (· != '|')).drop 1) (acc ++ bytes)
    | c :: rest, acc => pmDecode rest (acc.push c.toNat.toUInt8)
    | [], acc => acc

def ipv4 (s : String) : Option Nat :=
  match (s.splitOn ".").mapM natOf? with
  | some [a, b, c, d] => if a ≤ 255 && b ≤ 255 && c ≤ 255 && d ≤ 255 then some (((a * 256 + b) * 256 + c) * 256 + d) else none
  | _ => none

def ipv6 (s : String) : Option Nat :=
  let groups (g : String) : Option (List Nat) :=
    if g.isEmpty then some [] else
    (g.splitOn ":").mapM fun h => if isHexGroup h then (h.toList.foldl (fun acc c => acc * 16 + ((hexVal c.toNat.toUInt8).getD 0).toNat) 0) else none
  let expand (gs : List Nat) : Nat := gs.foldl (fun acc g => acc * 65536 + g) 0
  let withV4 (g : String) : Option (List Nat) :=   -- a trailing dotted quad counts as two groups
    match (g.splitOn ":").getLast? with
    | some last => if last.contains '.' then do
        let v4 ← ipv4 last
        let head ← groups (":".intercalate (g.splitOn ":").dropLast)
        some (head ++ [v4 / 65536, v4 % 65536])
      else groups g
    | none => groups g
  match s.splitOn "::" with
  | [a] => (withV4 a).bind fun gs => if gs.length == 8 then some (expand gs) else none
  | [a, b] => do
    let x ← groups a
    let y ← withV4 b
    if x.length + y.length ≤ 7 then some (expand (x ++ List.replicate (8 - x.length - y.length) 0 ++ y)) else none
  | _ => none

/-- `@ipMatch` (`06#ipmatch`): the value as an address inside any listed address or network. -/
def ipMatch (param : ByteArray) (v : ByteArray) : Bool :=
  let value := ofBytes v
  (((ofBytes param).splitOn ",").map trimBlanks).any fun e =>
    let (addr, pfx) := match e.splitOn "/" with | [a] => (a, none) | [a, p] => (a, natOf? p) | _ => ("", none)
    if addr.contains ':' then
      match ipv6 addr, ipv6 value with
      | some net, some ip => let bits := pfx.getD 128; let shift := 128 - bits; net >>> shift == ip >>> shift
      | _, _ => false
    else
      match ipv4 addr, ipv4 value with
      | some net, some ip => let bits := pfx.getD 32; let shift := 32 - bits; net >>> shift == ip >>> shift
      | _, _ => false

def validUrlEncoding (v : ByteArray) : Bool := go 0
where
  go (i : Nat) : Bool :=
    if i < v.size then
      if v[i]! == '%'.toUInt8 then (hexAt v (i + 1)).isSome && (hexAt v (i + 2)).isSome && go (i + 3) else go (i + 1)
    else true
  termination_by v.size - i
  decreasing_by all_goals simp_wf <;> omega

def validUtf8 (v : ByteArray) : Bool := go 0
where
  go (i : Nat) : Bool :=
    if h : i < v.size then
      if v[i] < 0x80 then go (i + 1)
      else match utf8Seq v i with
        | some (2, _) => go (i + 2) | some (3, _) => go (i + 3) | some (4, _) => go (i + 4) | _ => false
    else true
  termination_by v.size - i

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
  | "ge" => (atoi v ≥ atoi param, none)
  | "gt" => (atoi v > atoi param, none)
  | "le" => (atoi v ≤ atoi param, none)
  | "lt" => (atoi v < atoi param, none)
  | "pm" => ((pmPhrases param).any fun p => containsBytes (lowercase v) (lowercase p), none)
  | "unconditionalMatch" => (true, none)
  | "validateByteRange" =>
    let ranges := ((ofBytes param).splitOn ",").filterMap fun r => match r.splitOn "-" with
      | [a] => (natOf? a).map fun n => (n, n) | [a, b] => do pure (← natOf? a, ← natOf? b) | _ => none
    (v.toList.any fun b => !ranges.any fun (lo, hi) => lo ≤ b.toNat && b.toNat ≤ hi, none)
  | "validateUrlEncoding" => (!validUrlEncoding v, none)
  | "validateUtf8Encoding" => (!validUtf8 v, none)
  | "ipMatch" => (ipMatch param v, none)
  | _ => (false, none)

def setCaptures (tx : Tx) (caps : Array (Option ByteArray)) : Tx :=
  let keep := tx.tx.filter fun m => !(m.key.length == 1 && m.key.toList.all Char.isDigit)
  let new := (List.range (min caps.size 10)).filterMap fun i => (caps[i]!).map fun v => Member.mk (toString i) v
  { tx with tx := new ++ keep }

/-- `setvar` (`08#setvar`) on `TX`; other collections are not modelled. -/
def applySetvar (tx : Tx) (v : String) : Tx :=
  let (del, v) := if v.startsWith "!" then (true, dropFirst v) else (false, v)
  let (target, value) := match v.splitOn "=" with
    | [t] => (t, none) | t :: rest => (t, some ("=".intercalate rest)) | [] => ("", none)
  let (coll, key) := match target.splitOn "." with
    | c :: rest => (c, ".".intercalate rest) | [] => ("", "")
  if coll.toLower != "tx" then tx else
  let key := latin key
  let others := tx.tx.filter fun m => !keyEq m.key key
  let current := ((tx.tx.find? fun m => keyEq m.key key).map (·.value)).getD .empty
  if del then { tx with tx := others } else
  let newVal : ByteArray := match value with
    | none => text "1"
    | some s =>
      let e := expandMacros tx s
      let es := ofBytes e
      if es.startsWith "+" then text (toString (atoi current + atoi (text (dropFirst es))))
      else if es.startsWith "-" then text (toString (atoi current - atoi (text (dropFirst es))))
      else e
  { tx with tx := others ++ [⟨key, newVal⟩] }

/-- `ctl` (`03#ctl-timing`): rule edits immediate, `ruleEngine` at the next phase. -/
def applyCtl (tx : Tx) (v : String) : Tx :=
  let (opt, val) := match v.splitOn "=" with | [o] => (o, "") | o :: rest => (o, "=".intercalate rest) | [] => ("", "")
  let ranges (r : String) : List (Nat × Nat) := (parseRanges 0 [r]).toOption.getD []
  let ids (r : String) : List Nat := (ranges r).flatMap fun (a, z) => (List.range (z + 1 - a)).map (· + a)
  let target (t : String) : Option Variable := ((parseVariables 0 t).toOption.bind List.head?)
  match opt with
  | "ruleEngine" => { tx with nextMode := modeOf val }
  | "ruleRemoveById" => { tx with removedIds := tx.removedIds ++ ids val }
  | "ruleRemoveByTag" => { tx with removedTags := tx.removedTags ++ [val] }
  | "ruleRemoveTargetById" => match val.splitOn ";" with
    | [r, t] => match target t with
      | some tv => { tx with removedTargets := tx.removedTargets ++ (ids r).map (·, tv) }
      | none => tx
    | _ => tx
  | "ruleRemoveTargetByTag" => match val.splitOn ";" with
    | [tag, t] => match target t with
      | some tv => { tx with removedTagTargets := tx.removedTagTargets ++ [(tag, tv)] }
      | none => tx
    | _ => tx
  | "requestBodyAccess" => { tx with bodyAccess := some (val.toLower == "on") }
  | "requestBodyProcessor" => { tx with bodyProcessor := some val }
  | "forceRequestBodyVariable" => { tx with forceBody := val.toLower == "on" }
  | _ => tx

/-- The non-disruptive effects of a matching rule or inherited list. -/
def applyActions (tx : Tx) (as : List Action) : Tx :=
  as.foldl (fun tx a => match a.name, a.value with
    | "setvar", some v => applySetvar tx v
    | "ctl", some v => applyCtl tx v
    | _, _ => tx) tx

/-- Exclusions a chain inherits from `ctl:ruleRemoveTarget*` for this transaction. -/
def targetExclusions (tx : Tx) (c : Chain) : List Variable :=
  (tx.removedTargets.filter (·.1 == c.id)).map (·.2) ++
  (tx.removedTagTargets.filter fun (t, _) => (tagsOf c).contains t).map (·.2)

/-- One rule of a chain (`02#secrule-structure`, `02#operator`, `08#multimatch`,
`06#unconditionalmatch`): the rule matches when some value matches, or, negated, when the
operator fails for every value and at least one value was selected. -/
def runRule (o : Oracle) (c : Chain) (r : Rule) (tx : Tx) : Tx × Bool :=
  match r.operator with
  | none => (applyActions tx r.actions, true)
  | some op =>
    let values := selectValues o tx r.variables (targetExclusions tx c)
    let param := expandMacros tx op.param
    let tfns := tfnList r.actions
    let multi := hasAction r.actions "multiMatch"
    let results := values.map fun (name, v) =>
      let stages := if multi then (tfns.foldl (fun (acc : List ByteArray) t => acc ++ [applyTfn t acc.getLast!]) [v])
                    else [tfns.foldl (fun w t => applyTfn t w) v]
      let hits := stages.filterMap fun w => let (ok, caps) := evalOperator o op.name param w; if ok then some (w, caps) else none
      (name, hits.getLast?, stages.getLast!)
    let matched := if op.negate then !values.isEmpty && results.all (·.2.1.isNone) else results.any (·.2.1.isSome)
    if !matched then (tx, false) else
    let hits := results.filterMap fun (n, h, _) => h.map fun (w, caps) => (n, w, caps)
    let (name, value, caps) := match hits.getLast? with
      | some h => h
      | none => match results.getLast? with | some (n, _, w) => (n, w, none) | none => ("", .empty, none)
    let tx := { tx with matchedVar := value, matchedVarName := name,
                        matchedVars := hits.map fun (n, w, _) => ⟨n, w⟩ }
    let tx := if hasAction r.actions "capture" then (match caps with | some cs => setCaptures tx cs | none => tx) else tx
    (applyActions tx r.actions, true)

/-- A chain: members in order, stopping at the first that does not match (`03#chains`). -/
def runChain (o : Oracle) (c : Chain) (tx : Tx) : Tx × Bool :=
  let tx := { tx with evaluated := tx.evaluated ++ [c.id] }
  (c.starter :: c.members).foldl (fun (tx, ok) r => if ok then runRule o c r tx else (tx, false)) (tx, true)

def removed (tx : Tx) (c : Chain) : Bool := tx.removedIds.contains c.id || (tagsOf c).any tx.removedTags.contains

def allowScopeOf (c : Chain) : AllowScope :=
  match actionValue c.starter.actions "allow" with | some "phase" => .phase | some "request" => .request | _ => .all

def redirectStatus (s : Option Nat) : Nat :=
  match s with | some n => if n == 301 || n == 302 || n == 303 || n == 307 then n else 302 | none => 302

/-- After a whole chain matched (`03#disruptive-actions`, `08#allow`): record, run the
inherited cumulative actions, and in mode `On` apply the disruptive action. -/
def afterMatch (c : Chain) (tx : Tx) : Tx :=
  let tx := applyActions { tx with triggered := tx.triggered ++ [c.id] } c.extra
  if tx.mode != .on then tx else
  match c.disruptive with
  | some "deny" => { tx with interruption := some ⟨c.id, "deny", c.status.getD 403⟩, ended := true }
  | some "drop" => { tx with interruption := some ⟨c.id, "drop", c.status.getD 403⟩, ended := true }
  | some "redirect" => { tx with interruption := some ⟨c.id, "redirect", redirectStatus c.status⟩, ended := true }
  | some "allow" => { tx with allow := some (allowScopeOf c), ended := true }
  | _ => tx

/-- Per-phase flow-control state (`03#flow-control`): local to the phase. -/
structure PhaseState where
  skip : Nat := 0
  skipAfter : Option String := none

def skipOf (c : Chain) : Nat := ((actionValue c.starter.actions "skip").bind natOf?).getD 0
def skipAfterOf (c : Chain) : Option String := actionValue c.starter.actions "skipAfter"
def labelMatches (c : Chain) (l : String) : Bool := toString c.id == l

/-- The rules of one phase in order. A pending `skipAfter` passes everything until a marker
or a rule id with that label; `skip` passes the next rules of the phase; chains of other
phases and removed chains are passed over; a match applies its actions and may end the
phase. -/
def runItems (o : Oracle) (phase : Nat) : List Item → PhaseState → Tx → Tx
  | [], _, tx => tx
  | item :: rest, ps, tx =>
    if tx.ended then tx else
    match item with
    | .marker l => runItems o phase rest (if ps.skipAfter == some l then { ps with skipAfter := none } else ps) tx
    | .chain c =>
      match ps.skipAfter with
      | some l => runItems o phase rest (if labelMatches c l then { ps with skipAfter := none } else ps) tx
      | none =>
        if c.phase != phase || removed tx c then runItems o phase rest ps tx
        else if ps.skip > 0 then runItems o phase rest { ps with skip := ps.skip - 1 } tx
        else
          let (tx', matched) := runChain o c tx
          if matched then runItems o phase rest ⟨skipOf c, skipAfterOf c⟩ (afterMatch c tx')
          else runItems o phase rest ps tx'

def allowPermits (a : Option AllowScope) (p : Nat) : Bool :=
  match a with | none => true | some .phase => true | some .request => p > 2 | some .all => p == 5

/-- Whether phase `p` runs (`03#phases`, `03#disruptive-actions`, `08#allow`): never with the
engine off; phase 5 always otherwise; phases 1–4 unless interrupted or allowed past. -/
def phaseRuns (tx : Tx) (p : Nat) : Bool :=
  tx.mode != .off && (p == 5 || (tx.interruption.isNone && allowPermits tx.allow p))

/-- Phase boundary: the mode chosen by `ctl:ruleEngine` applies, `allow:phase` expires,
the `MATCHED_*` variables are cleared (their value across rules is unspecified). -/
def startPhase (tx : Tx) : Tx :=
  { tx with mode := tx.nextMode, ended := false,
            allow := if tx.allow == some .phase then none else tx.allow,
            matchedVar := .empty, matchedVarName := "", matchedVars := [] }

/-- One phase: populate the store, cross the boundary, run the rules with fresh flow-control
state. -/
def step (o : Oracle) (items : List Item) (prepare : Nat → Tx → Store) (p : Nat) (tx : Tx) : Tx :=
  let tx := startPhase { tx with store := prepare p tx }
  if phaseRuns tx p then runItems o p items {} tx else tx

/-- A transaction: the five phases in order. -/
def runTransaction (o : Oracle) (items : List Item) (prepare : Nat → Tx → Store) (tx : Tx) : Tx :=
  [1, 2, 3, 4, 5].foldl (fun tx p => step o items prepare p tx) tx

end SecLang
```

(The guards' `run` helper: `def run (cfg : String) (store : Store) : Tx := match parseConfig [] cfg with | .ok c => runTransaction testOracle (effectiveItems testOracle c) (fun _ tx => if tx.store.isEmpty then store else tx.store) {} | .error _ => {}` and `def tri (tx : Tx) := tx.triggered`.) `lake build` → success; every guard passes. For termination of `validUrlEncoding.go` the `decreasing_by` may be unnecessary; drop it if the default succeeds.

- [ ] **Step 4: Commit** — `feat(formal): processing-model semantics: effective rules, phases, chains, flow control, ctl, setvar`.

---

### Task 4: Theorems

**Files:**
- Modify: `formal/SecLang/Semantics.lean` (append before `end SecLang`)

- [ ] **Step 1: State and prove**

```lean
/-! ## Theorems for the Divergence ADRs -/

/-- ADR-0017: a rule without `phase` runs in phase 2. -/
theorem phase_default (r : Rule) (h : actionValue r.actions "phase" = none) : chainPhase r = 2 := by
  simp [chainPhase, h]

/-- ADR-0017: the phase never comes from the default actions in force. -/
theorem phase_not_inherited (d₁ d₂ : List (Nat × List Action)) (r : Rule) :
    (mkChain d₁ r).phase = (mkChain d₂ r).phase := rfl

/-- ADR-0016: every phase starts with no pending `skipAfter` and no `skip` count; the state of
the previous phase is not consulted. -/
theorem skipAfter_ends_with_phase (o : Oracle) (items : List Item) (prepare : Nat → Tx → Store) (p : Nat) (tx : Tx) :
    step o items prepare p tx =
      (let tx' := startPhase { tx with store := prepare p tx }
       if phaseRuns tx' p then runItems o p items ⟨0, none⟩ tx' else tx') := rfl

/-- ADR-0016: a pending label that no later marker or rule id carries evaluates nothing for the
rest of its phase. -/
theorem skipAfter_missing (o : Oracle) (p k : Nat) (l : String) (items : List Item) (tx : Tx)
    (h : ∀ i ∈ items, (match i with | .marker m => m ≠ l | .chain c => labelMatches c l = false)) :
    (runItems o p items ⟨k, some l⟩ tx).evaluated = tx.evaluated := by
  induction items generalizing tx with
  | nil => rfl
  | cons i rest ih =>
    have hi := h i (List.mem_cons_self ..)
    have hr : ∀ j ∈ rest, (match j with | .marker m => m ≠ l | .chain c => labelMatches c l = false) :=
      fun j hj => h j (List.mem_cons_of_mem _ hj)
    cases i with
    | marker m =>
      simp only [runItems]
      split
      · rfl
      · have : (some l == some m) = false := by simp_all
        simp [this, ih hr]
    | chain c =>
      simp only [runItems]
      split
      · rfl
      · simp [hi, ih hr]

/-- An interruption in an earlier phase: phases 2–4 evaluate nothing. -/
theorem interrupted_phase_quiet (o : Oracle) (items : List Item) (prepare : Nat → Tx → Store) (p : Nat) (tx : Tx)
    (hp : p ≠ 5) (hi : tx.interruption.isSome) :
    (step o items prepare p tx).evaluated = tx.evaluated := by
  have : (p == 5) = false := by simpa using hp
  simp [step, startPhase, phaseRuns, this, hi]

/-- Phase 5 runs whenever the engine is not off at its boundary, interrupted or not. -/
theorem logging_phase_runs (tx : Tx) (h : tx.nextMode ≠ .off) : phaseRuns (startPhase tx) 5 = true := by
  simp [phaseRuns, startPhase, h]
```

`lake build` → success. If a proof needs a different tactic combination, adjust it (`simp_all`, `decide`, `omega`) but keep the statements; a theorem that cannot be closed is left as a ledgered `sorry`-free *removal*, never a `sorry`.

- [ ] **Step 2: Commit** — `feat(formal): theorems for ADR-0017, ADR-0016 and the interruption rule`.

---

### Task 5: Runner, first run, triage

**Files:**
- Create: `formal/EvalMain.lean`
- Modify: `formal/lakefile.toml` (third `lean_exe` `seclang-eval`, root `EvalMain`), `spec/03-processing-model.md`, `spec/08-actions.md`, `spec/02-grammar.md` as the run requires

- [ ] **Step 1: Runner**

```lean
import Lean.Data.Json
import SecLang

/-! Runs every engine profile the abstract transaction can carry through the processing model
and checks `triggered_rules`, `non_triggered_rules`, `interruption` and `no_interruption`.
Profiles needing features outside the model are reported as unsupported with the reason.
Exit 1 on any mismatch. -/
open Lean SecLang

structure Stage where
  title : String
  input : Request
  response : Option Response
  output : Json

structure Profile where
  path : String
  rules : String
  files : List (String × String)
  expectError : Bool
  stages : List Stage

def strD (j : Json) (k d : String) : String := ((j.getObjVal? k).bind Json.getStr?).toOption.getD d
def kvs (j : Json) (k : String) : List (String × String) :=
  match j.getObjVal? k with
  | .ok (.obj m) => m.toList.filterMap fun (n, v) => (v.getStr?).toOption.map (n, ·)
  | _ => []
def strs (j : Json) (k : String) : List (String × String) := kvs j k

def stageOf (title : String) (j : Json) : Except String Stage := do
  let st ← j.getObjVal? "stage"
  let inp := (st.getObjVal? "input").toOption.getD (Json.mkObj [])
  let req : Request := { method := strD inp "method" "GET", uri := strD inp "uri" "/", version := strD inp "version" "HTTP/1.1",
                         headers := kvs inp "headers", body := ((inp.getObjVal? "data").bind Json.getStr?).toOption,
                         remoteAddr := strD inp "remote_addr" "127.0.0.1" }
  let resp : Option Response := match st.getObjVal? "response" with
    | .ok r => some { status := ((r.getObjVal? "status").bind Json.getNat?).toOption.getD 200, headers := kvs r "headers", body := strD r "data" "" }
    | .error _ => none
  return ⟨title, req, resp, ← st.getObjVal? "output"⟩

def Profile.ofJson (j : Json) : Except String Profile := do
  let files : List (String × String) := kvs j "files"
  let tests ← (j.getObjVal? "tests") >>= Json.getArr?
  let stages ← tests.toList.flatMapM fun t => do
    let title := strD t "test_title" ""
    let ss ← (t.getObjVal? "stages") >>= Json.getArr?
    ss.toList.mapM (stageOf title)
  return { path := ← j.getObjVal? "path" >>= Json.getStr?, rules := ← j.getObjVal? "rules" >>= Json.getStr?,
           files, expectError := ← j.getObjVal? "expect_error" >>= Json.getBool?, stages }

/-- `SecRuleEngine` and the store settings from the configuration. -/
def settingsOf (cfg : Config) : Settings × Mode :=
  cfg.directives.foldl (fun (s, m) d => match d with
    | .setting _ "SecRuleEngine" [v] => (s, modeOf v)
    | .setting _ "SecArgumentSeparator" [v] => ({ s with argSep := v.toList.headD '&' }, m)
    | .setting _ "SecArgumentsLimit" [v] => ({ s with argsLimit := natOf? v }, m)
    | .setting _ "SecRequestBodyAccess" [v] => ({ s with requestBodyAccess := v.toLower == "on" }, m)
    | .setting _ "SecResponseBodyAccess" [v] => ({ s with responseBodyAccess := v.toLower == "on" }, m)
    | .setting _ "SecResponseBodyMimeType" vs => ({ s with mimeTypes := s.mimeTypes ++ vs }, m)
    | .setting _ "SecResponseBodyMimeTypesClear" _ => ({ s with mimeTypes := [] }, m)
    | _ => (s, m)) ({}, .off)

def implementedOperators : List String :=
  ["rx", "streq", "contains", "beginsWith", "endsWith", "within", "eq", "ge", "gt", "le", "lt", "pm",
   "unconditionalMatch", "validateByteRange", "validateUrlEncoding", "validateUtf8Encoding", "ipMatch"]
def unsupportedVariables : List String :=
  ["FILES", "FILES_NAMES", "FILES_COMBINED_SIZE", "MULTIPART_PART_HEADERS", "MULTIPART_STRICT_ERROR", "XML",
   "REQBODY_ERROR", "REQBODY_ERROR_MSG", "INBOUND_DATA_ERROR", "OUTBOUND_DATA_ERROR", "IP", "GLOBAL", "SESSION", "USER", "RESOURCE"]
def limitDirectives : List String := ["SecRequestBodyLimit", "SecResponseBodyLimit", "SecRequestBodyNoFilesLimit"]

/-- The first feature outside the model that a profile needs, if any. -/
def unsupportedReason (cfg : Config) (stages : List Stage) : Option String :=
  let rules := cfg.directives.filterMap fun | .rule r => some r | _ => none
  let ops := rules.filterMap fun r => r.operator.map (·.name)
  let vars := rules.flatMap fun r => r.variables.map (·.collection)
  let acts := rules.flatMap (·.actions)
  let dirs := cfg.directives.filterMap fun | .setting _ n _ => some n | _ => none
  if let some op := ops.find? (fun n => !implementedOperators.contains n) then some s!"operator @{op}"
  else if let some v := vars.find? unsupportedVariables.contains then some s!"variable {v}"
  else if let some a := acts.find? (fun a => ["initcol", "expirevar", "setsid", "setuid", "setrsc"].contains a.name) then some s!"action {a.name}"
  else if acts.any (fun a => a.name == "ctl" && (a.value.getD "").startsWith "requestBodyProcessor=" && !(a.value.getD "").toLower.endsWith "urlencoded") then some "body processor selected by ctl"
  else if let some d := dirs.find? limitDirectives.contains then some s!"directive {d}"
  else if stages.any (fun s => (s.output.getObjVal? "log_contains").toOption.isSome || (s.output.getObjVal? "no_log_contains").toOption.isSome) then some "log assertions"
  else if stages.any (fun s => s.input.body.isSome && (headerValue s.input.headers "Content-Type").any fun ct =>
            let c := ct.toLower; c.startsWith "multipart/" || c.startsWith "application/json" || c.endsWith "xml") then some "body processor"
  else none

def natList (j : Json) (k : String) : List Nat :=
  match (j.getObjVal? k).bind Json.getArr? with
  | .ok a => a.toList.filterMap fun x => (x.getNat?).toOption
  | .error _ => []

/-- Mismatches of one stage, in the adapters' wording. -/
def checkStage (o : Oracle) (items : List Item) (settings : Settings) (mode : Mode) (st : Stage) : List String :=
  let prepare : Nat → Tx → Store := fun p tx => match p with
    | 1 => phase1Store settings st.input
    | 2 => phase2Store settings st.input (tx.bodyAccess.getD settings.requestBodyAccess) tx.bodyProcessor tx.forceBody tx.store
    | 3 => phase3Store st.response tx.store
    | 4 => phase4Store settings st.response tx.store
    | _ => tx.store
  let tx := runTransaction o items prepare { mode, nextMode := mode }
  let out := st.output
  let want := natList out "triggered_rules"
  let wantNot := natList out "non_triggered_rules"
  let m1 := (want.filter fun id => !tx.triggered.contains id).map fun id => s!"rule {id} expected triggered"
  let m2 := (wantNot.filter tx.triggered.contains).map fun id => s!"rule {id} expected not triggered"
  let m3 := match out.getObjVal? "interruption" with
    | .ok i =>
      let rid := ((i.getObjVal? "rule_id").bind Json.getNat?).toOption
      let act := ((i.getObjVal? "action").bind Json.getStr?).toOption
      let status := ((i.getObjVal? "status").bind Json.getNat?).toOption
      match tx.interruption with
      | none => [s!"expected interruption by rule {rid.getD 0}, got none"]
      | some got =>
        (if rid.any (· != got.ruleId) then [s!"interruption rule_id {got.ruleId}, expected {rid.getD 0}"] else []) ++
        (if act.any (· != got.action) then [s!"interruption action {got.action}, expected {act.getD ""}"] else []) ++
        (if status.any (· != got.status) then [s!"interruption status {got.status}, expected {status.getD 0}"] else [])
    | .error _ => []
  let m4 := match out.getObjVal? "no_interruption" with
    | .ok (.bool true) => match tx.interruption with | some i => [s!"unexpected interruption by rule {i.ruleId}"] | none => []
    | _ => []
  m1 ++ m2 ++ m3 ++ m4

def main (args : List String) : IO UInt32 := do
  let some file := args.head? | IO.eprintln "usage: seclang-eval engine-rules.json"; return 2
  let txt ← IO.FS.readFile file
  let profiles ← IO.ofExcept (Json.parse txt >>= Json.getArr? >>= (·.mapM Profile.ofJson))
  let o : Oracle := ⟨Regex.search⟩
  let mut stages := 0
  let mut mismatches := 0
  let mut unsupported := 0
  for p in profiles do
    if p.expectError then IO.println s!"{p.path}: skipped (expect_error)"; continue
    match parseConfig p.files p.rules with
    | .error e => IO.println s!"{p.path}: cannot load: line {e.line}: {e.msg}  <-- MISMATCH"; mismatches := mismatches + 1
    | .ok cfg =>
      match unsupportedReason cfg p.stages with
      | some why => IO.println s!"{p.path}: unsupported ({why})"; unsupported := unsupported + 1
      | none =>
        let (settings, mode) := settingsOf cfg
        let items := effectiveItems o cfg
        for st in p.stages do
          stages := stages + 1
          let ms := checkStage o items settings mode st
          if ms.isEmpty then IO.println s!"{p.path} [{st.title}]: ok"
          else
            mismatches := mismatches + 1
            IO.println s!"{p.path} [{st.title}]: MISMATCH"
            for m in ms do IO.println s!"  {m}"
  IO.println s!"{stages} stages, {mismatches} mismatches, {unsupported} unsupported profiles"
  return if mismatches == 0 then 0 else 1
```

- [ ] **Step 2: First run** — `cd formal && lake build && lake exe seclang-eval .lake/engine-rules.json | tee <scratch>/eval1.txt | tail -1`; list `grep -A3 MISMATCH` and `grep unsupported`. Triage each mismatch: model defect (fix Lean, add a guard), profile defect (fix YAML, rerun the Coraza adapter), spec defect (fix text). Each unsupported reason must be one of the design's categories; anything else is a model gap to close. Record in the ledger. Rerun until 0 mismatches.
- [ ] **Step 3: Spec alignment** — `08#skipafter` semantics: "On match, skip to the `SecMarker LABEL`, or the rule with `id:LABEL`, …" to match `03#flow-control`; `02#operator`: after "the rule matches when the operator is false for *every* selected value" add "and at least one value was selected (`06-operators.md#unconditionalmatch`)"; plus whatever Step 2 surfaced. `uv run python tools/validate.py` → 0.
- [ ] **Step 4: Commit** — `feat(formal): transaction runner over the engine profiles; spec: skipAfter targets, negation on empty selections`.

---

### Task 6: CI, docs, review, finish

**Files:**
- Modify: `.github/workflows/validate.yml`, `AGENTS.md`, `README.md`, `formal/README.md`

- [ ] **Step 1: CI** — after the `seclang-parse` step add `- run: lake exe seclang-eval .lake/engine-rules.json` with `working-directory: formal`.
- [ ] **Step 2: Docs** — `formal/README.md`: a "Processing model" section with the command, what unsupported means (a profile needing a body processor other than URL-encoded, body limits, persistent collections, libinjection operators or log assertions), and the theorem names. `AGENTS.md` `formal/` row: `SecLang/Semantics.lean` (spec 03 over the AST, three ADR theorems) and `seclang-eval`; "Before you commit" line extended with `&& lake exe seclang-eval .lake/engine-rules.json`. `README.md` row: "…and the processing model of spec 03 run against the engine profiles".
- [ ] **Step 3: Verify** — validator 0; tools tests OK; Coraza adapter ok; all three Lean executables green; Hugo smoke passes.
- [ ] **Step 4: Commit** — `ci(formal): run the processing-model check; docs: formal/ covers spec 03`.
- [ ] **Step 5: Review and finish** — fresh reviewer on the most capable model (design, Review Focus, ledger rulings; ask it to compare the semantics against chapter 03 sentence by sentence and to hunt for configurations whose outcome differs from what the prose says); one fix pass; `superpowers:finishing-a-development-branch`, merge to main locally, never push.
