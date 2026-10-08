import SecLang.Names
/-! AST, lexer and parser for SecLang configuration text (`spec/01-lexical.md`,
`spec/02-grammar.md`, `spec/04-directives.md`). -/
namespace SecLang

structure ConfigError where
  line : Nat
  msg : String
  deriving Repr, BEq

abbrev Parse := Except ConfigError

def isBlank (c : Char) : Bool := c == ' ' || c == '\t'

/-- A logical line with the number of the physical line it starts on. -/
structure Line where
  num : Nat
  text : List Char

/-- Physical lines: split on LF, a trailing CR dropped (`01#lines-and-directives`). -/
def physicalLines (s : String) : List (List Char) :=
  (s.splitOn "\n").map fun l =>
    let cs := l.toList
    if cs.getLast? == some '\r' then cs.dropLast else cs

def dropTrailingBlanks (cs : List Char) : List Char := (cs.reverse.dropWhile isBlank).reverse

/-- Blank and comment lines are dropped (`01#comments`); the rest keeps its number. -/
def emitLine (l : Line) : List Line :=
  match l.text.dropWhile isBlank with
  | [] => []
  | '#' :: _ => []
  | body => [⟨l.num, dropTrailingBlanks body⟩]

/-- Logical lines: continuation joined first (`01#line-continuation`, ADR-0013), then blank
and comment lines dropped. -/
def logicalLines (s : String) : List Line :=
  go (physicalLines s) 1 none
where
  go : List (List Char) → Nat → Option Line → List Line
    | [], _, none => []
    | [], _, some l => emitLine l
    | p :: rest, n, acc =>
      let t := dropTrailingBlanks p
      let cur : Line := match acc with
        | none => ⟨n, t⟩
        | some l => ⟨l.num, l.text ++ t⟩
      if t.getLast? == some '\\' then
        go rest (n + 1) (some ⟨cur.num, cur.text.dropLast⟩)
      else emitLine cur ++ go rest (n + 1) none

/-- The directive name and its arguments (`01#quoting-and-escapes`, `02` `directive`):
bare tokens end at whitespace; a `"`-delimited argument keeps whitespace, `\"` yields `"`,
any other backslash pair is passed through unchanged. -/
partial def splitArgs (l : Line) : Parse (List String) := go l.text [] []
where
  err (m : String) : Parse (List String) := .error ⟨l.num, m⟩
  go : List Char → List Char → List String → Parse (List String)
    | [], [], acc => .ok acc.reverse
    | [], cur, acc => .ok (String.ofList cur.reverse :: acc).reverse
    | c :: rest, cur, acc =>
      if isBlank c then
        if cur.isEmpty then go rest [] acc else go rest [] (String.ofList cur.reverse :: acc)
      else if c == '"' && cur.isEmpty then quoted rest [] acc
      else go rest (c :: cur) acc
  quoted : List Char → List Char → List String → Parse (List String)
    | [], _, _ => err "unterminated quoted argument"
    | '\\' :: '"' :: rest, cur, acc => quoted rest ('"' :: cur) acc
    | '\\' :: c :: rest, cur, acc => quoted rest (c :: '\\' :: cur) acc
    | '"' :: rest, cur, acc =>
      match rest with
      | [] => .ok (String.ofList cur.reverse :: acc).reverse
      | c :: _ => if isBlank c then go rest [] (String.ofList cur.reverse :: acc)
                  else err "a closing quote must be followed by whitespace"
    | c :: rest, cur, acc => quoted rest (c :: cur) acc

#guard (logicalLines "a\r\nb\n\n  # c\nd \\\n  e\n# f \\\n  g\nh").map (fun l => (l.num, String.ofList l.text))
  == [(1, "a"), (2, "b"), (5, "d   e"), (9, "h")]
#guard (logicalLines "x \\").map (fun l => String.ofList l.text) == ["x"]
#guard (splitArgs ⟨1, "SecRule   ARGS_GET:a\t\"@streq 1\"     \"id:1,phase:1\"".toList⟩).toOption
  == some ["SecRule", "ARGS_GET:a", "@streq 1", "id:1,phase:1"]
#guard (splitArgs ⟨1, "SecRule ARGS \"@streq say \\\"hi\\\" now\" \"x\"".toList⟩).toOption
  == some ["SecRule", "ARGS", "@streq say \"hi\" now", "x"]
#guard (splitArgs ⟨1, "SecRule ARGS \"a\\\\b\"".toList⟩).toOption == some ["SecRule", "ARGS", "a\\\\b"]
#guard (splitArgs ⟨3, "SecRule ARGS \"unterminated".toList⟩) matches .error ⟨3, _⟩
#guard (splitArgs ⟨4, "SecRule \"abc\"def".toList⟩) matches .error ⟨4, _⟩
#guard (splitArgs ⟨1, "SecArgumentSeparator ;".toList⟩).toOption == some ["SecArgumentSeparator", ";"]

inductive Selector
  | key (k : String) | regex (re : String) | xpath (p : String)
  deriving Repr, BEq

structure Variable where
  negate : Bool
  count : Bool
  collection : String      -- canonical spelling
  selector : Option Selector
  deriving Repr, BEq

structure Operator where
  negate : Bool
  name : String            -- canonical spelling
  param : String
  deriving Repr, BEq

structure Action where
  name : String            -- canonical spelling
  value : Option String    -- quotes removed; `t:` values canonical
  deriving Repr, BEq

def err (line : Nat) (m : String) : Parse α := .error ⟨line, m⟩

def dropFirst (s : String) : String := String.ofList (s.toList.drop 1)
def trimBlanks (s : String) : String := String.ofList (dropTrailingBlanks (s.toList.dropWhile isBlank))

def isIdentChar (c : Char) : Bool := c.isAlphanum || c == '_'

/-- `02#variable-list`, `02#variable-selectors`: `[!|&]COLLECTION[:selector]`; the selector
is `/re/`, a key, or for `XML` an XPath expression (`05#xml`). -/
def parseVariable (line : Nat) (s : String) : Parse Variable := do
  let (negate, s) := if s.startsWith "!" then (true, dropFirst s) else (false, s)
  let (count, s) := if !negate && s.startsWith "&" then (true, dropFirst s) else (false, s)
  if (negate && s.startsWith "&") || (count && s.startsWith "!") then
    err line s!"'&' and '!' are mutually exclusive in '{s}'"
  let (name, sel) := match s.splitOn ":" with
    | [c] => (c, none)
    | c :: rest => (c, some (":".intercalate rest))
    | [] => ("", none)
  if name.isEmpty || !name.toList.all isIdentChar then err line s!"invalid variable name '{name}'"
  let some (canon, shape) := findVariable name | err line s!"unknown variable '{name}'"
  let selector ← match sel with
    | none => pure none
    | some sel =>
      if shape == .scalar then err line s!"'{canon}' is a scalar and takes no selector"
      else if canon == "XML" then pure (some (.xpath sel))
      else if sel.startsWith "/" then
        if sel.length ≥ 2 && sel.endsWith "/" then pure (some (.regex (String.ofList ((sel.toList.drop 1).dropLast))))
        else err line s!"unterminated regular expression selector '{sel}'"
      else if sel.isEmpty || sel.toList.any isBlank then err line s!"invalid selector '{sel}'"
      else pure (some (.key sel))
  return ⟨negate, count, canon, selector⟩

def parseVariables (line : Nat) (s : String) : Parse (List Variable) :=
  (s.splitOn "|").mapM (parseVariable line)

def natOf? (s : String) : Option Nat := if s.isEmpty then none else s.toNat?

/-- IPv4 `a.b.c.d`. -/
def isIPv4 (s : String) : Bool :=
  let parts := s.splitOn "."
  parts.length == 4 && parts.all fun p => p.length ≤ 3 && (natOf? p).any (· ≤ 255)

def isHexGroup (h : String) : Bool :=
  !h.isEmpty && h.length ≤ 4 && h.toList.all fun c => c.isAlphanum && (hexVal c.toNat.toUInt8).isSome

/-- Number of 16-bit groups in a `:`-separated run; a trailing dotted IPv4 counts as two. -/
def ipv6Groups (s : String) : Option Nat :=
  if s.isEmpty then some 0 else
  let parts := s.splitOn ":"
  match parts.getLast? with
  | some last =>
    if last.contains '.' then
      if isIPv4 last && parts.dropLast.all isHexGroup then some (parts.length + 1) else none
    else if parts.all isHexGroup then some parts.length else none
  | none => none

/-- IPv6: hex groups, at most one `::`, eight groups in all, optional IPv4 tail. -/
def isIPv6 (s : String) : Bool :=
  match s.splitOn "::" with
  | [a] => ipv6Groups a == some 8
  | [a, b] => match ipv6Groups a, ipv6Groups b with
    | some x, some y => x + y ≤ 7 && !a.contains '.'
    | _, _ => false
  | _ => false

/-- `06#ipmatch`: every entry an address with an optional in-range prefix (ADR-0024). -/
def checkIpMatch (line : Nat) (param : String) : Parse Unit :=
  (param.splitOn ",").forM fun e => do
    let e := trimBlanks e
    let (addr, pfx) := match e.splitOn "/" with
      | [a] => (a, none) | [a, p] => (a, some p) | _ => ("", some "x")
    let v6 := addr.contains ':'
    let prefixOk := match pfx with | none => true | some p => (natOf? p).any (· ≤ if v6 then 128 else 32)
    let ok := (if v6 then isIPv6 addr else isIPv4 addr) && prefixOk
    if !ok then err line s!"invalid @ipMatch entry '{e}'" else pure ()

/-- `06#validatebyterange`: decimal bytes or `LOW-HIGH` ranges. -/
def checkByteRange (line : Nat) (param : String) : Parse Unit := do
  if (trimBlanks param).isEmpty then err line "@validateByteRange needs at least one range"
  (param.splitOn ",").forM fun r => do
    let ok := match (trimBlanks r).splitOn "-" with
      | [a] => (natOf? a).any (· ≤ 255)
      | [a, b] => match natOf? a, natOf? b with | some x, some y => x ≤ y && y ≤ 255 | _, _ => false
      | _ => false
    if !ok then err line s!"invalid @validateByteRange entry '{r}'" else pure ()

/-- `02#operator`: `[!]@name [param]`, or the implicit `@rx` parameter. -/
def parseOperator (line : Nat) (s : String) : Parse Operator := do
  let (negate, s) := if s.startsWith "!" then (true, dropFirst s) else (false, s)
  if !s.startsWith "@" then return ⟨negate, "rx", s⟩
  let body := (dropFirst s).toList
  let name := String.ofList (body.takeWhile fun c => !isBlank c)
  let param := String.ofList ((body.dropWhile fun c => !isBlank c).dropWhile isBlank)
  let some canon := findOperator name | err line s!"unknown operator '@{name}'"
  if canon == "ipMatch" then checkIpMatch line param
  if canon == "validateByteRange" then checkByteRange line param
  return ⟨negate, canon, param⟩

/-- Split an action list on commas outside single quotes (`02#action-list`). -/
def splitActions (s : String) : List String := go s.toList [] [] false
where
  go : List Char → List Char → List String → Bool → List String
    | [], cur, acc, _ => (String.ofList cur.reverse :: acc).reverse
    | '\\' :: '\'' :: rest, cur, acc, inQ => go rest ('\'' :: '\\' :: cur) acc inQ
    | '\'' :: rest, cur, acc, inQ => go rest ('\'' :: cur) acc (!inQ)
    | ',' :: rest, cur, acc, false => go rest [] (String.ofList cur.reverse :: acc) false
    | c :: rest, cur, acc, inQ => go rest (c :: cur) acc inQ

/-- Strip one pair of single quotes and unescape `\'`. -/
def unquoteValue (v : String) : String :=
  if v.length ≥ 2 && v.startsWith "'" && v.endsWith "'" then
    (String.ofList ((v.toList.drop 1).dropLast)).replace "\\'" "'"
  else v

def phaseNumber (v : String) : Option Nat :=
  match v.toLower with
  | "1" => some 1 | "2" => some 2 | "3" => some 3 | "4" => some 4 | "5" => some 5
  | "request" => some 2 | "response" => some 4 | "logging" => some 5 | _ => none

def severityNames : List String :=
  ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]

def oneOf (choices : List String) (v : String) : Bool := choices.contains v.toLower

/-- `ID` or `A-B` with `A <= B` (`03#rule-exceptions`). -/
def parseRanges (line : Nat) (args : List String) : Parse (List (Nat × Nat)) :=
  args.mapM fun a => match a.splitOn "-" with
    | [x] => match natOf? x with | some n => pure (n, n) | none => err line s!"invalid rule id '{a}'"
    | [x, y] => match natOf? x, natOf? y with
      | some m, some n => if m ≤ n then pure (m, n) else err line s!"invalid range '{a}': start greater than end"
      | _, _ => err line s!"invalid range '{a}'"
    | _ => err line s!"invalid range '{a}'"

/-- Single directive arguments by kind (`04`). -/
def checkArg (line : Nat) (k : ArgKind) (v : String) : Parse Unit :=
  let enum (choices : List String) : Parse Unit :=
    if oneOf choices v then pure () else err line s!"'{v}' is not one of {choices}"
  match k with
  | .onOff => enum ["on", "off"]
  | .onOffDetectionOnly => enum ["on", "off", "detectiononly"]
  | .onOffRelevantOnly => enum ["on", "off", "relevantonly"]
  | .onOffOnlyArgs => enum ["on", "off", "onlyargs"]
  | .rejectProcessPartial => enum ["reject", "processpartial"]
  | .nativeJson => enum ["native", "json"]
  | .serialConcurrent => enum ["serial", "concurrent"]
  | .abortWarn => enum ["abort", "warn"]
  | .zeroOne => enum ["0", "1"]
  | .nat => if (natOf? v).isSome then pure () else err line s!"'{v}' is not a number"
  | .level09 => if (natOf? v).any (· ≤ 9) then pure () else err line s!"'{v}' is not a level 0-9"
  | .octal => if !v.isEmpty && v.toList.all (fun c => '0' ≤ c && c ≤ '7') then pure () else err line s!"'{v}' is not an octal mode"
  | .auditParts => if !v.isEmpty && v.toList.all (fun c => ('A' ≤ c && c ≤ 'K') || c == 'Z') then pure ()
                   else err line s!"invalid audit log parts '{v}': letters A-K and Z only"
  | .char => if v.length == 1 then pure () else err line s!"'{v}' is not a single character"
  | .text => pure ()

/-- `08#ctl` and the `ctl:` option sections; returns `option=value` with the canonical option. -/
def checkCtl (line : Nat) (v : String) : Parse String := do
  let (opt, val) := match v.splitOn "=" with
    | [o] => (o, "") | o :: rest => (o, "=".intercalate rest) | [] => ("", "")
  let some (canon, kind) := findCtl opt | err line s!"unknown ctl option '{opt}'"
  let enum (choices : List String) : Parse Unit :=
    if oneOf choices val then pure () else err line s!"ctl:{canon} takes one of {choices}, not '{val}'"
  match kind with
  | .onOff => enum ["on", "off"]
  | .onOffDetectionOnly => enum ["on", "off", "detectiononly"]
  | .onOffRelevantOnly => enum ["on", "off", "relevantonly"]
  | .onOffOnlyArgs => enum ["on", "off", "onlyargs"]
  | .parts => if val.length ≥ 2 && (val.startsWith "+" || val.startsWith "-") then checkArg line .auditParts (dropFirst val)
              else err line "ctl:auditLogParts takes +LETTERS or -LETTERS"
  | .processor => enum ["urlencoded", "xml", "json"]
  | .nat => if (natOf? val).isSome then pure () else err line s!"ctl:{canon} takes a number"
  | .idRange => discard (parseRanges line [val])
  | .idRangeTargets => match val.splitOn ";" with
    | [r, t] => do discard (parseRanges line [r]); discard (parseVariables line t)
    | _ => err line s!"ctl:{canon} takes ID;TARGET"
  | .textTargets => match val.splitOn ";" with
    | [_, t] => discard (parseVariables line t)
    | _ => err line s!"ctl:{canon} takes REGEX;TARGET"
  | .text => pure ()
  return s!"{canon}={val}"

/-- `08#setvar`: `[!]COLL.key[=VALUE]`. -/
def checkSetvar (line : Nat) (v : String) : Parse Unit := do
  let (del, v) := if v.startsWith "!" then (true, dropFirst v) else (false, v)
  let (target, value) := match v.splitOn "=" with
    | [t] => (t, none) | t :: rest => (t, some ("=".intercalate rest)) | [] => ("", none)
  if !target.contains '.' || target.startsWith "." || target.endsWith "." then err line s!"setvar target '{target}' is not COLL.key"
  if del && value.isSome then err line s!"setvar:!{target} takes no value"

/-- One action (`02#action-list`; value kinds from `08`). -/
def parseAction (line : Nat) (raw : String) : Parse Action := do
  let s := trimBlanks raw
  let (name, value) := match s.splitOn ":" with
    | [n] => (trimBlanks n, none) | n :: rest => (trimBlanks n, some (unquoteValue (":".intercalate rest))) | [] => ("", none)
  let some (canon, kind, _) := findAction name | err line s!"unknown action '{name}'"
  let need (what : String) : Parse String := match value with
    | some v => pure v | none => err line s!"{canon} needs a value: {what}"
  match kind with
  | .none => return ⟨canon, value⟩
  | .allow => match value with
    | none => return ⟨canon, none⟩
    | some v => if oneOf ["phase", "request"] v then return ⟨canon, some v.toLower⟩ else err line "allow takes phase or request"
  | .id =>
    let v ← need "a positive integer"
    if (natOf? v).any (· > 0) then return ⟨canon, some v⟩ else err line s!"invalid id '{v}'"
  | .phase =>
    let v ← need "1-5, request, response or logging"
    if (phaseNumber v).isSome then return ⟨canon, some v⟩ else err line s!"invalid phase '{v}'"
  | .severity =>
    let v ← need "0-7 or a level name"
    if (natOf? v).any (· ≤ 7) || oneOf severityNames v then return ⟨canon, some v⟩ else err line s!"invalid severity '{v}'"
  | .nat =>
    let v ← need "a number"
    if (natOf? v).isSome then return ⟨canon, some v⟩ else err line s!"{canon} takes a number, not '{v}'"
  | .transformation =>
    let v ← need "a transformation name"
    let some t := findTransformation v | err line s!"unknown transformation '{v}'"
    return ⟨canon, some t⟩
  | .ctl =>
    let v ← need "OPTION=VALUE"
    return ⟨canon, some (← checkCtl line v)⟩
  | .setvar =>
    let v ← need "COLL.key=VALUE"
    checkSetvar line v
    return ⟨canon, some v⟩
  | .label =>
    let v ← need "a label"
    if v.isEmpty then err line s!"{canon} needs a label" else return ⟨canon, some v⟩
  | .text => return ⟨canon, value⟩

def parseActions (line : Nat) (s : String) : Parse (List Action) :=
  (splitActions s).mapM (parseAction line)

#guard (parseVariables 1 "ARGS_GET:a|!ARGS_GET:skip|&TX:/^x/|XML://@*").toOption ==
  some [⟨false, false, "ARGS_GET", some (.key "a")⟩, ⟨true, false, "ARGS_GET", some (.key "skip")⟩,
        ⟨false, true, "TX", some (.regex "^x")⟩, ⟨false, false, "XML", some (.xpath "//@*")⟩]
#guard (parseVariables 1 "REQUEST_URI:x") matches .error _          -- selector on a scalar
#guard (parseVariables 1 "ARGS:/unterminated") matches .error _
#guard (parseVariables 1 "NOPE") matches .error _
#guard (parseVariables 1 "!&ARGS") matches .error _
#guard (parseVariables 1 "args_get") matches .ok [⟨false, false, "ARGS_GET", none⟩]
#guard (parseOperator 1 "@streq  a b").toOption == some ⟨false, "streq", "a b"⟩
#guard (parseOperator 1 "!@PMF words.txt").toOption == some ⟨true, "pmFromFile", "words.txt"⟩
#guard (parseOperator 1 "!^abc$").toOption == some ⟨true, "rx", "^abc$"⟩
#guard (parseOperator 1 "@detectSQLi").toOption == some ⟨false, "detectSQLi", ""⟩
#guard (parseOperator 1 "@nope x") matches .error _
#guard (parseOperator 1 "@ipMatch 192.0.2.1,198.51.100.0/24,2001:db8::/32") matches .ok _
#guard (parseOperator 1 "@ipMatch 192.0.2.1,10.0.0.0/100") matches .error _
#guard (parseOperator 1 "@validateByteRange 9,10,13,32-126") matches .ok _
#guard (parseOperator 1 "@validateByteRange 9,x") matches .error _
#guard (parseActions 1 "id:1, phase:request,deny,status:403,msg:'a, b \\' c',t:LOWERCASE,ctl:ruleEngine=Off").toOption ==
  some [⟨"id", some "1"⟩, ⟨"phase", some "request"⟩, ⟨"deny", none⟩, ⟨"status", some "403"⟩,
        ⟨"msg", some "a, b ' c"⟩, ⟨"t", some "lowercase"⟩, ⟨"ctl", some "ruleEngine=Off"⟩]
#guard (parseActions 1 "id:'7',severity:'WARNING',redirect:https://x/,setvar:!tx.d,setvar:tx.e=%{tx.a},allow:phase") matches .ok _
#guard (parseActions 1 "nope") matches .error _
#guard (parseActions 1 "id:0") matches .error _
#guard (parseActions 1 "phase:6") matches .error _
#guard (parseActions 1 "severity:8") matches .error _
#guard (parseActions 1 "t:frobnicate") matches .error _
#guard (parseActions 1 "ctl:responseBodyProcessor=X") matches .error _
#guard (parseActions 1 "ctl:ruleRemoveTargetById=7150;ARGS_GET:a") matches .ok _
#guard (parseActions 1 "ctl:ruleRemoveById=200-100") matches .error _
#guard (parseActions 1 "setvar:tx") matches .error _
#guard (parseRanges 1 ["5010", "5012-5013"]).toOption == some [(5010, 5010), (5012, 5013)]
#guard (parseRanges 1 ["200-100"]) matches .error _
#guard (checkArg 1 .auditParts "AXYZ") matches .error _
#guard (checkArg 1 .auditParts "ABIJDEFHZ") matches .ok _
#guard (checkArg 1 .onOffDetectionOnly "detectiononly") matches .ok _
#guard (checkArg 1 .octal "0600") matches .ok _
#guard (checkArg 1 .octal "0699") matches .error _

end SecLang
