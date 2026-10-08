import Lean.Data.Json
import SecLang

/-! Loads every engine profile's configuration (from `tools/engine_rules.py` JSON) and
checks the model's verdict against `expect_error`. Exit 1 on any mismatch. -/
open Lean SecLang

structure Profile where
  path : String
  rules : String
  files : List (String × String)
  expectError : Bool

def Profile.ofJson (j : Json) : Except String Profile := do
  let files : List (String × String) ← match j.getObjVal? "files" with
    | .ok (.obj kvs) => kvs.toList.mapM fun (k, v) => do
        let s ← v.getStr?
        return (k, s)
    | _ => pure []
  return { path := ← j.getObjVal? "path" >>= Json.getStr?
           rules := ← j.getObjVal? "rules" >>= Json.getStr?
           files
           expectError := ← j.getObjVal? "expect_error" >>= Json.getBool? }

def main (args : List String) : IO UInt32 := do
  let some file := args.head? | IO.eprintln "usage: seclang-parse engine-rules.json"; return 2
  let txt ← IO.FS.readFile file
  let profiles ← IO.ofExcept (Json.parse txt >>= Json.getArr? >>= (·.mapM Profile.ofJson))
  let mut mismatches := 0
  for p in profiles do
    let (accepted, text) := match parseConfig p.files p.rules with
      | .ok _ => (true, "accepted")
      | .error e => (false, s!"rejected: line {e.line}: {e.msg}")
    let bad := accepted == p.expectError
    IO.println s!"{p.path}: {text}{if bad then "  <-- MISMATCH" else ""}"
    if bad then mismatches := mismatches + 1
  IO.println s!"{profiles.size} profiles, {mismatches} mismatches"
  return if mismatches == 0 then 0 else 1
