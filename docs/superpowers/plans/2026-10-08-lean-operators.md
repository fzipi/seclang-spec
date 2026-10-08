# Lean Stage 4: Operators and Multipart Bodies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every library-free operator of spec 06 is a Lean definition checked against `tests/unit/operators`, and the multipart body processor of spec 09 populates the store so the multipart profiles run through the processing model.

**Architecture:** `Operators.lean` takes the operator code out of `Semantics.lean`, adds the six missing operators and an `implemented` name list, and widens `Oracle` to position-returning searches so `verify*` can scan from offsets with anchors relative to the whole subject. `Regex.lean` gains scoped and mid-pattern flag groups. `Main.lean` runs `type: op` cases. `Request.lean` gains `parseMultipart` and the multipart branch of `phase2Store`; `EvalMain.lean` drops the multipart variables from its unsupported list.

**Tech Stack:** Lean `v4.34.1` (`export PATH="$HOME/.elan/bin:$PATH"`), Lake 5; Python via `uv`.

**Spec:** `docs/superpowers/specs/2026-10-08-lean-operators-design.md`; `spec/06-operators.md`, `spec/09-body-processors.md`, `spec/05-variables.md` (FILES*, MULTIPART_*). Engine source: `cd ~/Workspace/OWASP/modsecurity/modsecurity && git show v2/master:apache2/re_operators.c` (`msre_op_containsWord_execute`, `luhn_verify`, `msre_op_verifyCC_execute`, `cpf_verify`, `ssn_verify`).

## Global Constraints

- `Semantics.lean` keeps importing only the `Oracle` abstraction; `Operators.lean` is where regexes are run.
- Guards first, watched failing. Every commit passes `cd formal && lake build && lake exe seclang-check && lake exe seclang-parse .lake/engine-rules.json && lake exe seclang-eval .lake/engine-rules.json`; validator 0; tools tests; Coraza adapter when a profile or corpus file changes.
- Operator and transformation runs share one runner and one output shape.
- Commit messages end with the two attribution lines. Never push.

## Review Focus

1. `verifyCC` on a 17-digit input where only a 16-digit suffix is Luhn-valid (`15484605089158216` with the grouped CRS pattern). Expected: no match, because `^` is anchored to the whole value, not to the search offset; guard in Task 1.
2. `containsWord` with the parameter at the very end of the value and preceded by `_`. Expected: no match (`_` is a word byte); guard in Task 1.
3. A multipart body with a bare LF line ending. Expected: parts still extracted where possible and `MULTIPART_STRICT_ERROR` 1; guard in Task 3.
4. A multipart `Content-Type` whose boundary is quoted (`boundary="XX"`). Expected: parsed as `XX`; guard in Task 3.
5. An operator unit case whose regex uses lookahead. Expected: reported as skipped with the reason, not as a failure; checked on `rx-pcre-extra.json` in Task 2.

---

### Task 1: Operators module, oracle with offsets, scoped regex flags

**Files:**
- Create: `formal/SecLang/Operators.lean`
- Modify: `formal/SecLang/Regex.lean`, `formal/SecLang/Semantics.lean`, `formal/SecLang.lean`, `formal/EvalMain.lean` (`implementedOperators` → `Operators.implemented`; oracle construction)

**Interfaces:**
- Produces: `Regex.searchAt : String → ByteArray → Nat → Option (Array (Option (Nat × Nat)))` (positions; `search` derived), `Re.flagged`; `Oracle` (`rxAt`) with `Oracle.rx`; `evalOperator`, `containsWord`, `luhn`, `verifyCC`, `verifyCPF`, `verifySSN`, `implemented : List String`.

- [ ] **Step 1: Guards (RED)** — in `Regex.lean`:

```lean
#guard searchStr "(?i:abc)D" "ABCD" == some [some "ABCD"]
#guard (searchStr "(?i:abc)d" "ABCD").isNone
#guard (searchStr "a(?i)b" "aB").isSome
#guard (searchStr "(?i:(sleep\\((\\s*?)(\\d*?)(\\s*?)\\)|benchmark\\((.*?)\\,(.*?)\\)))" "SELECT pg_sleep(10);").isSome
#guard (searchAt "^b" "ab".toUTF8 1).isNone                     -- `^` stays anchored to the whole subject
#guard (searchAt "b" "ab".toUTF8 1).map (·.toList) == some [some (1, 2)]
```

In a new `Operators.lean` (header only, guards at the end; `testOracle` defined there):

```lean
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
```

`lake build` → unknown identifiers.

- [ ] **Step 2: Regex** — add `| flagged (f : Flags) (r : Re)` to `Re` (the flags *in force inside*, computed at parse time from the enclosing flags). Thread the current flags through the parser: `P` gains `flags : Flags`; `parseAtom` on `'(' :: '?' :: rest` reads the letters `[ims]+`; if `':'` follows, parse a group with `p.flags` updated and wrap it in `.flagged newFlags`; if `')'` follows (mid-pattern `(?i)`), set `p.flags := newFlags` and return `.seq []` (the new flags then apply to the rest of the parse, which is the rest of the enclosing group, as in PCRE). Remove `leadingFlags`; `compile` starts with `{}` flags and returns `p.flags` as the top-level flags only for nodes not wrapped. In `m`: `| .flagged f' r => m f' s r i caps k`. Every atom that consults flags (`lit`, `any`, `cls`, `bol`, `eol`) is wrapped by the parser in `.flagged p.flags` only when `p.flags ≠ {}`… simpler: make the parser wrap *every* group body and every top-level sequence in `.flagged p.flags` when flags changed, i.e. `parseAlt` returns `.flagged p.flags (…)` whenever `p.flags` differs from the flags it started with. Add `searchAt`:

```lean
/-- Leftmost match at or after `start`; group positions. Anchors see the whole subject. -/
def searchAt (pat : String) (subject : ByteArray) (start : Nat) : Option (Array (Option (Nat × Nat))) :=
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
    tryFrom start (s.size + 1 - start)

def search (pat : String) (subject : ByteArray) : Option (Array (Option ByteArray)) :=
  (searchAt pat subject 0).map fun caps => caps.map fun
    | some (a, b) => some (subject.extract a b)
    | none => none
```

- [ ] **Step 3: Operators.lean** — move from `Semantics.lean`: `Oracle` (now `structure Oracle where rxAt : String → ByteArray → Nat → Option (Array (Option (Nat × Nat)))` with `def Oracle.rx (o) (re) (v) := (o.rxAt re v 0).map fun caps => caps.map fun | some (a, b) => some (v.extract a b) | none => none`), `atoi`, `containsBytes`, `pmPhrases`, `ipv4`, `hexGroupValue`, `v6Groups`, `v6Tail`, `ipv6`, `ipMatch`, `validUrlEncoding`, `validUtf8`, `evalOperator`. `Semantics.lean` imports `SecLang.Operators` and loses those definitions; `rxName` stays (`(o.rx re (text s)).isSome`). Add:

```lean
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
  let trivial := (List.range 10).map (fun d => List.replicate 11 d) ++ [[0,1,2,3,4,5,6,7,8,9,0]]
  if trivial.contains ds then false else
  let check (k : Nat) : Nat :=      -- k = 9 or 10 digits weighted (k+1) .. 2
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

/-- `verify*` scan (v2): regex matches from offset 0 upward, the whole match checked by `ok`;
the next search starts one past the failing match's start. -/
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
```

(`b > a` is PCRE's `NOTEMPTY`.) Extend `evalOperator` with `"containsWord" => (containsWord v param, none)`, `"strmatch" => (containsBytes v param, none)`, `"noMatch" => (false, none)`, `"verifyCC" => (verifyWith o luhn (ofBytes param) v, none)`, `"verifyCPF" => (verifyWith o cpfValid …)`, `"verifySSN" => (verifyWith o ssnValid …)`. Add

```lean
/-- Operators the model defines (`06`); the runner skips the others by name. -/
def implemented : List String :=
  ["beginsWith", "contains", "containsWord", "endsWith", "eq", "ge", "gt", "ipMatch", "le", "lt", "noMatch",
   "pm", "rx", "streq", "strmatch", "unconditionalMatch", "validateByteRange", "validateUrlEncoding",
   "validateUtf8Encoding", "verifyCC", "verifyCPF", "verifySSN", "within"]

def testOracle : Oracle := ⟨Regex.searchAt⟩
```

and remove `testOracle` from `Semantics.lean`. `EvalMain.lean`: `let o : Oracle := ⟨Regex.searchAt⟩`, `implementedOperators` replaced by `implemented`. `lake build` → success; all three executables unchanged in output.

- [ ] **Step 4: Commit** — `feat(formal): operators module with containsWord, strmatch, noMatch, verifyCC, verifyCPF, verifySSN; regex scoped flags and offset search`.

---

### Task 2: Operator unit runner, first run, spec outlines

**Files:**
- Modify: `formal/Main.lean`, `spec/06-operators.md`

- [ ] **Step 1: Runner** — `Case` gains `type : String`, `param : Option String`, `reGroups : List String` (`re_groups` absent → `[]`). Outcomes:

```lean
inductive Outcome | pass | fail (msg : String) | skip (why : String)

def checkOp (c : Case) : Outcome :=
  match toBytes c.input, toBytes (c.param.getD "") with
  | .error e, _ | _, .error e => .fail e
  | .ok inp, .ok param =>
    let pstr := ofBytes param
    if (c.name == "rx" || c.name.startsWith "verify") && (match Regex.compile pstr with | .error _ => true | .ok _ => false) then
      .skip s!"@{c.name} {pstr.quote}: regex outside the Core subset"
    else
      let (ok, caps) := evalOperator testOracle c.name param inp
      if ok != (c.ret == 1) then .fail s!"@{c.name} {pstr.quote} on {c.input.quote}: matched={ok}, expected ret={c.ret}"
      else if ok && !c.reGroups.isEmpty then
        let got := (caps.getD #[]).toList.map fun g => ofBytes (g.getD .empty)
        match (List.range c.reGroups.length).find? fun i => got.getD i "" != c.reGroups.getD i "" with
        | some i => .fail s!"@{c.name} {pstr.quote} on {c.input.quote}: group {i} = {(got.getD i "<none>").quote}, expected {(c.reGroups.getD i "").quote}"
        | none => .pass
      else .pass
```

`runFile` dispatches on the first case's `type`: `"op"` → `implemented.contains name` else skipped; counts passes, failures and skips; prints `N passed, M failed, K skipped` (skips listed with their reason). Transformations unchanged.

- [ ] **Step 2: First run** — `cd formal && lake build && lake exe seclang-check | tee <scratch>/ops1.txt | grep -v "0 failed"`; triage every failure (model, corpus or spec), rerun until zero failures. Expected skips: `detectSQLi.json`, `detectXSS.json` (not formalized) and the two lookahead cases of `rx-pcre-extra.json`.
- [ ] **Step 3: Spec** — expand the Extended outlines in `spec/06-operators.md`: `containsWord` ("Matches when the parameter occurs in the value at a position preceded by the start of the value or a byte that is not an ASCII letter, digit or `_`, and followed by the end or such a byte; the empty parameter matches every value (ModSecurity v2 `re_operators.c` `msre_op_containsWord_execute`)."), `strmatch` ("…byte-wise, like `contains`…"), `verifyCC` ("The parameter is a regular expression. Each match, searched from successive offsets with anchors relative to the whole value, is checked with the Luhn algorithm over its digits; the first Luhn-valid match matches (v2 `msre_op_verifyCC_execute`, `luhn_verify`)."), `verifyCPF` and `verifySSN` with the digit rules above and their v2 functions. Validator 0.
- [ ] **Step 4: Commit** — `feat(formal): unit runner covers operators; spec: Extended operator outlines state their algorithms`.

---

### Task 3: Multipart bodies

**Files:**
- Modify: `formal/SecLang/Request.lean`, `formal/EvalMain.lean`

- [ ] **Step 1: Guards (RED)** — in `Request.lean`:

```lean
def mpBody : String := "--XX\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\nhello\r\n--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nabc\r\n--XX--\r\n"
#guard (parseArgs '&' none "a=1&&b=2").map (·.key) == ["a", "b"]
#guard ((parseMultipart "XX" mpBody).1.map fun p => (p.name, p.filename, ofBytes p.content)) == [("t", none, "hello"), ("f", some "a.txt", "abc")]
#guard (parseMultipart "XX" mpBody).2 == false
#guard (parseMultipart "XX" "--XX\nContent-Disposition: form-data; name=\"t\"\n\nhello\n--XX--\n").2 == true
#guard (parseMultipart "XX" "--XX\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\nhello\r\n").2 == true
#guard (parseMultipart "XX" "junk\r\n--XX\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\nhello\r\n--XX--\r\n").2 == true
#guard headerParam "multipart/form-data; boundary=\"XX\"" "boundary" == some "XX"
#guard headerParam "multipart/form-data; boundary=XX" "boundary" == some "XX"
#guard (let s := phase2Store { requestBodyAccess := true } { method := "POST", uri := "/", headers := [("Content-Type", "multipart/form-data; boundary=XX")], body := some mpBody } true none false (phase1Store {} { uri := "/" })
        ((s.get "ARGS_POST").map (fun m => (m.key, ofBytes m.value)), (s.get "FILES").map (fun m => (m.key, ofBytes m.value)), (s.get "FILES_NAMES").map (ofBytes ·.value),
         (s.get "FILES_COMBINED_SIZE").map (ofBytes ·.value), (s.get "MULTIPART_STRICT_ERROR").map (ofBytes ·.value), (s.get "REQBODY_PROCESSOR").map (ofBytes ·.value), (s.get "REQUEST_BODY").length))
  == ([("t", "hello")], [("f", "a.txt")], ["f"], ["3"], ["0"], ["MULTIPART"], 0)
#guard ((phase2Store { requestBodyAccess := true } { method := "POST", uri := "/", headers := [("Content-Type", "multipart/form-data; boundary=XX")], body := some mpBody } true none false (phase1Store {} { uri := "/" })).get "MULTIPART_PART_HEADERS").map (fun m => (m.key, (ofBytes m.value).startsWith "Content-Disposition")) == [("t", true), ("f", true)]
```

- [ ] **Step 2: Implement**

```lean
/-- `parseArgs`: an empty pair is ignored (`09#urlencoded`). -/
  -- in parseArgs: `.filter (!·.isEmpty)` on the split pieces before mapping

structure Part where
  name : String
  filename : Option String
  headers : String
  content : ByteArray

/-- A `key=value` parameter of a `;`-separated header value, quotes removed. -/
def headerParam (v : String) (key : String) : Option String :=
  ((v.splitOn ";").map trimBlanks).findSome? fun p =>
    match p.splitOn "=" with
    | k :: rest@(_ :: _) =>
      if k.toLower == key.toLower then
        let val := "=".intercalate rest
        some (if val.length ≥ 2 && val.startsWith "\"" && val.endsWith "\"" then String.ofList ((val.toList.drop 1).dropLast) else val)
      else none
    | _ => none

/-- One part: the header block up to the blank line, then the content. -/
def parsePart (piece : String) : Part :=
  let (hdrs, content) := match piece.splitOn "\r\n\r\n" with
    | [h] => (h, "")
    | h :: rest => (h, "\r\n\r\n".intercalate rest)
    | [] => ("", "")
  let disposition := ((hdrs.splitOn "\r\n").find? fun l => l.toLower.startsWith "content-disposition:").map fun l => dropFirst (String.ofList (l.toList.dropWhile (· != ':')))
  { name := (disposition.bind (headerParam · "name")).getD "", filename := disposition.bind (headerParam · "filename"),
    headers := hdrs, content := text content }

/-- RFC 7578 (`09#multipart`): parts and whether an anomaly was seen (data before the first
boundary, a bare LF line ending, or no closing delimiter). -/
def parseMultipart (boundary : String) (body : String) : List Part × Bool :=
  let delim := "--" ++ boundary
  let bareLF := (body.toList.zip ('\r' :: body.toList)).any fun (c, prev) => c == '\n' && prev != '\r'
  if !body.startsWith delim then ([], true) else
  let pieces := (String.ofList (body.toList.drop delim.length)).splitOn ("\r\n" ++ delim)
  match pieces.getLast? with
  | none => ([], true)
  | some last =>
    let closed := last.startsWith "--"
    let parts := (pieces.dropLast.filter fun p => p.startsWith "\r\n").map fun p => parsePart (String.ofList (p.toList.drop 2))
    (parts, bareLF || !closed)
```

In `phase2Store`, after `proc` is known: when `proc == "MULTIPART"`, `let (parts, bad) := match headerParam ct "boundary" with | some b => parseMultipart b body | none => ([], true)`; `post := parts.filter (·.filename.isNone) |>.map fun p => ⟨latin p.name, p.content⟩`; `files := parts.filterMap fun p => p.filename.map fun f => Member.mk (latin p.name) (text f)`; set `FILES`, `FILES_NAMES` (`namesOf files`), `FILES_COMBINED_SIZE` (sum of file contents' sizes), `MULTIPART_PART_HEADERS` (`parts.map fun p => ⟨latin p.name, text p.headers⟩`), `MULTIPART_STRICT_ERROR` (`natText (if bad then 1 else 0)`); `REQUEST_BODY` stays empty unless forced (ADR-0022). The URL-encoded branch is unchanged. `EvalMain.lean`: remove `FILES`, `FILES_NAMES`, `FILES_COMBINED_SIZE`, `MULTIPART_PART_HEADERS`, `MULTIPART_STRICT_ERROR` from `unsupportedVariables` and `multipart/` from the body-processor check. `lake build` → success.

- [ ] **Step 3: Run** — `lake exe seclang-eval .lake/engine-rules.json | tail -1` → `… 0 mismatches, 17 unsupported profiles`; the multipart profiles print `ok`. Validator 0.
- [ ] **Step 4: Commit** — `feat(formal): multipart body processor; URL-encoded empty pairs ignored`.

---

### Task 4: Docs, review, finish

**Files:**
- Modify: `formal/README.md`, `AGENTS.md`, `README.md`

- [ ] **Step 1: Docs** — `formal/README.md`: `seclang-check` covers `tests/unit/operators` too (which operators, what "skipped" means for a regex outside the subset); the processing-model section's unsupported list drops multipart. `AGENTS.md` and `README.md` rows: "every transformation of spec 07 and every library-free operator of spec 06", "URL-encoded and multipart bodies".
- [ ] **Step 2: Verify** — validator 0; tools tests; Coraza adapter; the three executables; Hugo smoke.
- [ ] **Step 3: Commit** — `docs: formal/ covers operators and multipart bodies`.
- [ ] **Step 4: Review and finish** — fresh reviewer (most capable model; ask for a differential check of the operators against the v2 C where feasible and a sentence-by-sentence read of 09#multipart); one fix pass; `superpowers:finishing-a-development-branch`, merge to main locally, never push.
