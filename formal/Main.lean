import Lean.Data.Json
import SecLang

/-!
Runs `tests/unit/transformations/*.json` against the Lean definitions. Per file: skipped
when its transformation is not formalized, otherwise `N passed, M failed` plus one line per
mismatch in the adapters' wording. Exit 1 when anything failed or could not be loaded.
-/
open Lean SecLang

/-- The transformations the model defines, by corpus name. -/
def formalized : List (String × (ByteArray → ByteArray)) :=
  [("lowercase", lowercase), ("hexEncode", hexEncode), ("urlDecodeUni", urlDecodeUni),
   ("cssDecode", cssDecode), ("base64Decode", base64Decode),
   ("uppercase", uppercase), ("removeNulls", removeNulls), ("replaceNulls", replaceNulls),
   ("removeWhitespace", removeWhitespace), ("trimLeft", trimLeft), ("trimRight", trimRight),
   ("trim", trim), ("length", length), ("parityEven7bit", parityEven7bit),
   ("parityOdd7bit", parityOdd7bit), ("parityZero7bit", parityZero7bit),
   ("compressWhitespace", compressWhitespace), ("hexDecode", hexDecode), ("urlDecode", urlDecode),
   ("urlEncode", urlEncode), ("sqlHexDecode", sqlHexDecode)]

/-- A unit-tier byte string (every code point ≤ U+00FF, one byte each; `tests/README.md`). -/
def toBytes (s : String) : Except String ByteArray := do
  let mut out := ByteArray.emptyWithCapacity s.length
  for c in s.toList do
    if c.toNat > 255 then throw s!"not a byte string: {s.quote}"
    out := out.push c.toNat.toUInt8
  return out

def ofBytes (b : ByteArray) : String :=
  String.ofList (b.toList.map fun x => Char.ofNat x.toNat)

structure Case where
  name : String
  input : String
  output : String
  ret : Nat

def Case.ofJson (j : Json) : Except String Case := do
  return {
    name := ← j.getObjVal? "name" >>= Json.getStr?
    input := ← j.getObjVal? "input" >>= Json.getStr?
    output := ← j.getObjVal? "output" >>= Json.getStr?
    ret := ← j.getObjVal? "ret" >>= Json.getNat? }

/-- The mismatch for one case, if any. -/
def check (f : ByteArray → ByteArray) (c : Case) : Except String (Option String) := do
  let got := ofBytes (f (← toBytes c.input))
  if got != c.output then
    return some s!"t:{c.name} on {c.input.quote}: output {got.quote}, expected {c.output.quote}"
  if (got != c.input) != (c.ret == 1) then
    return some s!"t:{c.name} on {c.input.quote}: changed={got != c.input}, expected ret={c.ret}"
  return none

/-- Runs one corpus file; `true` when it passed or was skipped. -/
def runFile (path : System.FilePath) : IO Bool := do
  let name := path.fileName.getD path.toString
  let txt ← IO.FS.readFile path
  match Json.parse txt >>= Json.getArr? >>= (·.mapM Case.ofJson) with
  | .error e => IO.println s!"{name}: cannot load: {e}"; return false
  | .ok cases =>
    let some first := cases[0]? | IO.println s!"{name}: skipped (no cases)"; return true
    let some f := formalized.lookup first.name | IO.println s!"{name}: skipped (not formalized)"; return true
    let mut failed : Array String := #[]
    for c in cases do
      match check f c with
      | .ok none => pure ()
      | .ok (some m) => failed := failed.push m
      | .error e => failed := failed.push e
    IO.println s!"{name}: {cases.size - failed.size} passed, {failed.size} failed"
    for m in failed do IO.println s!"  {m}"
    return failed.isEmpty

def main (args : List String) : IO UInt32 := do
  let dir : System.FilePath := args.headD "../tests/unit/transformations"
  let files := (← dir.readDir).filter (·.path.extension == some "json")
    |>.qsort (·.fileName < ·.fileName)
  let mut ok := true
  let mut checked := 0
  for e in files do
    ok := (← runFile e.path) && ok
    checked := checked + 1
  if checked == 0 then
    IO.println s!"no corpus files found in {dir}"
    return 1
  return if ok then 0 else 1
