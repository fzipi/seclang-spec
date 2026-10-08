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

end SecLang
