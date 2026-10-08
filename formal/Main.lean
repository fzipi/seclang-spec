import Lean.Data.Json
import SecLang

/-!
Runs `tests/unit/transformations/*.json` against the Lean definitions. Per file: skipped
when its transformation is not formalized, otherwise `N passed, M failed` plus one line per
mismatch in the adapters' wording. Exit 1 when anything failed or could not be loaded.
-/
open Lean SecLang

def formalized := byName

structure Case where
  name : String
  type : String
  input : String
  output : String
  ret : Nat
  param : Option String
  reGroups : List String

def Case.ofJson (j : Json) : Except String Case := do
  let strOpt (k : String) : Option String := ((j.getObjVal? k).bind Json.getStr?).toOption
  let groups := match (j.getObjVal? "re_groups").bind Json.getArr? with
    | .ok a => a.toList.filterMap fun g => (g.getStr?).toOption
    | .error _ => []
  return {
    name := ← j.getObjVal? "name" >>= Json.getStr?
    type := (strOpt "type").getD "tfn"
    input := ← j.getObjVal? "input" >>= Json.getStr?
    output := (strOpt "output").getD ""
    ret := ← j.getObjVal? "ret" >>= Json.getNat?
    param := strOpt "param"
    reGroups := groups }

inductive Outcome | pass | fail (msg : String) | skip (why : String)

/-- A transformation case: output and `ret` as `output != input`. -/
def checkTfn (f : ByteArray → ByteArray) (c : Case) : Outcome :=
  match toBytes c.input with
  | .error e => .fail e
  | .ok inp =>
    let got := ofBytes (f inp)
    if got != c.output then
      .fail s!"t:{c.name} on {c.input.quote}: output {got.quote}, expected {c.output.quote}"
    else if (got != c.input) != (c.ret == 1) then
      .fail s!"t:{c.name} on {c.input.quote}: changed={got != c.input}, expected ret={c.ret}"
    else .pass

/-- An operator case: `ret` as the match, `re_groups` as the captures in order; a regular
expression outside the Core subset is skipped, not failed. -/
def checkOp (c : Case) : Outcome :=
  match toBytes c.input, toBytes (c.param.getD "") with
  | .error e, _ => .fail e
  | _, .error e => .fail e
  | .ok inp, .ok param =>
    let pstr := ofBytes param
    let name := (findOperator c.name).getD c.name      -- names match case-insensitively (ADR-0002)
    if (name == "rx" || name.startsWith "verify") && (match Regex.compile pstr with | .error _ => true | .ok _ => false) then
      .skip s!"@{c.name} {pstr.quote}: regex outside the Core subset"
    else
      let (ok, caps) := evalOperator testOracle name param inp
      if ok != (c.ret == 1) then
        .fail s!"@{c.name} {pstr.quote} on {c.input.quote}: matched={ok}, expected ret={c.ret}"
      else if ok && !c.reGroups.isEmpty then
        let got := (caps.getD #[]).toList.map fun g => ofBytes (g.getD .empty)
        match (List.range c.reGroups.length).find? (fun i => got.getD i "" != c.reGroups.getD i "") with
        | some i => .fail s!"@{c.name} {pstr.quote} on {c.input.quote}: group {i} = {(got.getD i "<none>").quote}, expected {(c.reGroups.getD i "").quote}"
        | none => .pass
      else .pass

/-- Runs one corpus file; `true` when it passed or was skipped. -/
def runFile (path : System.FilePath) : IO Bool := do
  let name := path.fileName.getD path.toString
  let txt ← IO.FS.readFile path
  match Json.parse txt >>= Json.getArr? >>= (·.mapM Case.ofJson) with
  | .error e => IO.println s!"{name}: cannot load: {e}"; return false
  | .ok cases =>
    let some first := cases[0]? | IO.println s!"{name}: skipped (no cases)"; return true
    let check : Option (Case → Outcome) :=
      if first.type == "op" then (if (findOperator first.name).any implemented.contains then some checkOp else none)
      else (formalized.lookup first.name).map checkTfn
    let some check := check | IO.println s!"{name}: skipped (not formalized)"; return true
    let mut failed : Array String := #[]
    let mut skipped : Array String := #[]
    for c in cases do
      match check c with
      | .pass => pure ()
      | .fail m => failed := failed.push m
      | .skip m => skipped := skipped.push m
    IO.println s!"{name}: {cases.size - failed.size - skipped.size} passed, {failed.size} failed{if skipped.isEmpty then "" else s!", {skipped.size} skipped"}"
    for m in failed do IO.println s!"  {m}"
    for m in skipped do IO.println s!"  skipped: {m}"
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
