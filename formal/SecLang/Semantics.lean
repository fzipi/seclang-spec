import SecLang.Syntax
import SecLang.Digest
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
  (vars ++ exclusions.map fun (e : Variable) => { e with negate := true }).foldl step []

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

/-- `ctl` (`03#ctl-timing`): rule edits are immediate; `ruleEngine` applies to the later
phases and, for `DetectionOnly` (and `On`), to the rest of the current phase as well, so a
later rule of the same phase no longer interrupts; `Off` leaves the current phase running
(the model's choice where the spec is silent). -/
def applyCtl (tx : Tx) (v : String) : Tx :=
  let (opt, val) := match v.splitOn "=" with | [o] => (o, "") | o :: rest => (o, "=".intercalate rest) | [] => ("", "")
  let ranges (r : String) : List (Nat × Nat) := (parseRanges 0 [r]).toOption.getD []
  let ids (r : String) : List Nat := (ranges r).flatMap fun (a, z) => (List.range (z + 1 - a)).map (· + a)
  let target (t : String) : Option Variable := ((parseVariables 0 t).toOption.bind List.head?)
  match opt with
  | "ruleEngine" =>
    let m := modeOf val
    { tx with nextMode := m, mode := if m == .off then tx.mode else m }
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
      let stages : List ByteArray := if multi then tfns.foldl (fun acc t => acc ++ [applyTfn t (acc.getLastD v)]) [v]
                    else [tfns.foldl (fun w t => applyTfn t w) v]
      let hits := stages.filterMap fun w => let (ok, caps) := evalOperator o op.name param w; if ok then some (w, caps) else none
      (name, hits.getLast?, stages.getLastD v)
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
      have hne : (some l == some m) = false := by
        rw [beq_eq_false_iff_ne]
        intro e
        exact hi (Option.some.inj e).symm
      simp only [runItems]
      split
      · rfl
      · simp [hne]
        exact ih tx hr
    | chain c =>
      simp only [runItems]
      split
      · rfl
      · simp [hi]
        exact ih tx hr

/-- An interruption in an earlier phase: phases 2–4 evaluate nothing. -/
theorem interrupted_phase_quiet (o : Oracle) (items : List Item) (prepare : Nat → Tx → Store) (p : Nat) (tx : Tx)
    (hp : p ≠ 5) (hi : tx.interruption.isSome) :
    (step o items prepare p tx).evaluated = tx.evaluated := by
  have hp' : (p == 5) = false := by simpa using hp
  have hn : tx.interruption ≠ none := by
    intro e
    rw [e] at hi
    simp at hi
  simp [step, startPhase, phaseRuns, hp', hn]

/-- Phase 5 runs whenever the engine is not off at its boundary, interrupted or not. -/
theorem logging_phase_runs (tx : Tx) (h : tx.nextMode ≠ .off) : phaseRuns (startPhase tx) 5 = true := by
  simp only [phaseRuns, startPhase]
  cases hm : tx.nextMode with
  | off => exact absurd hm h
  | on => rfl
  | detectionOnly => rfl

def testOracle : Oracle := ⟨Regex.search⟩
def run (cfg : String) (store : Store) : Tx :=
  match parseConfig [] cfg with
  | .ok c => runTransaction testOracle (effectiveItems testOracle c) (fun _ tx => if tx.store.isEmpty then store else tx.store) {}
  | .error _ => {}
def tri (tx : Tx) : List Nat := tx.triggered
def demoStore (args : List (String × String)) : Store :=
  [("ARGS_GET", args.map fun (k, v) => ⟨k, text v⟩), ("ARGS", args.map fun (k, v) => ⟨k, text v⟩), ("REQUEST_HEADERS", [⟨"X-P", text "1"⟩])]

#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 2\" \"id:2,phase:1,pass\"" (demoStore [("a", "1")])) == [1]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,skip:1\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:1,pass,skipAfter:END\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:4,phase:1,pass\"\nSecMarker END\nSecRule ARGS_GET:a \"@streq 1\" \"id:5,phase:1,pass\"" (demoStore [("a", "1")])) == [1, 3, 5]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,skipAfter:3\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:4,phase:1,pass\"" (demoStore [("a", "1")])) == [1, 4]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,skipAfter:NOWHERE\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:2,pass\"" (demoStore [("a", "1")])) == [1, 3]
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
#guard tri (run "SecAction \"id:1,phase:1,pass,nolog,setvar:tx.a=5,setvar:tx.a=+3,setvar:tx.b=%{tx.a},setvar:tx.c=x,setvar:!tx.c,setvar:tx.d\"\nSecRule TX:a \"@eq 8\" \"id:2,phase:1,pass\"\nSecRule TX:b \"@streq 8\" \"id:3,phase:1,pass\"\nSecRule &TX:c \"@eq 0\" \"id:4,phase:1,pass\"\nSecRule TX:d \"@eq 1\" \"id:5,phase:1,pass\"" (demoStore [])) == [1, 2, 3, 4, 5]
#guard tri (run "SecRule ARGS_GET:a \"@rx ^(\\w+)-(\\w+)$\" \"id:1,phase:1,pass,capture,setvar:tx.first=%{TX.1}\"\nSecRule TX:first \"@streq foo\" \"id:2,phase:1,pass\"\nSecRule TX:0 \"@streq foo-bar\" \"id:3,phase:1,pass\"\nSecRule TX:2 \"@streq bar\" \"id:4,phase:1,pass\"" (demoStore [("a", "foo-bar")])) == [1, 2, 3, 4]
#guard tri (run "SecRule ARGS_GET:a \"@streq abc\" \"id:1,phase:1,pass,t:lowercase,t:hexEncode,multiMatch\"\nSecRule ARGS_GET:a \"@streq abc\" \"id:2,phase:1,pass,t:lowercase,t:hexEncode\"\nSecRule ARGS_GET:a \"@streq ABC\" \"id:3,phase:1,pass,t:lowercase,t:none\"" (demoStore [("a", "ABC")])) == [1, 3]
#guard tri (run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,tag:'drop-me'\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a|ARGS_GET:b \"@streq 1\" \"id:3,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:4,phase:1,deny\"\nSecRuleRemoveByTag drop-me\nSecRuleRemoveById 2\nSecRuleUpdateTargetById 3 \"!ARGS_GET:a\"\nSecRuleUpdateActionById 4 \"pass\"" (demoStore [("a", "1")])) == [4]
#guard tri (run "SecRule &ARGS_GET \"@eq 2\" \"id:1,phase:1,pass\"\nSecRule ARGS_GET|!ARGS_GET:skip \"@streq x\" \"id:2,phase:1,pass\"" (demoStore [("skip", "x"), ("b", "2")])) == [1]
#guard tri (run "SecRule ARGS_GET:a \"@streq %{tx.expected}\" \"id:2,phase:1,pass\"\nSecAction \"id:1,phase:1,pass,nolog,setvar:tx.expected=secret\"\nSecRule ARGS_GET:a \"@streq %{TX.EXPECTED}\" \"id:3,phase:1,pass\"" (demoStore [("a", "secret")])) == [1, 3]
#guard tri (run "SecRule ARGS_GET:a \"@streq hello\" \"id:1,phase:1,pass,t:lowercase,chain\"\n  SecRule MATCHED_VAR \"@streq hello\" \"t:none\"\nSecRule ARGS_GET:a \"@streq hello\" \"id:2,phase:1,pass,t:lowercase,chain\"\n  SecRule MATCHED_VAR_NAME \"@streq ARGS_GET:a\" \"t:none\"\nSecRule ARGS_GET:b|ARGS_GET:c \"@rx ^v\" \"id:3,phase:1,pass,chain\"\n  SecRule &MATCHED_VARS \"@eq 2\" \"t:none\"" (demoStore [("a", "HeLLo"), ("b", "v1"), ("c", "v2")])) == [1, 2, 3]
#guard tri (run "SecRule REQUEST_HEADERS:X-P \"@streq 1\" \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=2;ARGS_GET:a\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:1,pass\"" (demoStore [("a", "1")])) == [1, 3]
#guard tri (run "SecRule ARGS_GET:q \"@pm forbidden other\" \"id:1,phase:1,pass\"\nSecRule &ARGS_GET \"@lt 3\" \"id:2,phase:1,pass\"\nSecRule ARGS_GET:a \"@eq 0\" \"id:3,phase:1,pass\"\nSecRule ARGS_GET:q \"@contains FORB\" \"id:4,phase:1,pass\"" (demoStore [("q", "this is FORBIDDEN"), ("a", "abc")])) == [1, 2, 3, 4]

#guard (let tx := run "SecRule ARGS_GET:a \"@streq 1\" \"id:1,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:2,phase:1,deny\"\nSecRule ARGS_GET:a \"@streq 1\" \"id:3,phase:2,deny\"" (demoStore [("a", "1")])
        (tx.triggered, tx.interruption)) == ([1, 2, 3], none)

end SecLang
