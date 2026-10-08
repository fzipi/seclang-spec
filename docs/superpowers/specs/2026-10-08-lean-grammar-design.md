# Lean Formalization, Stage 2: Lexical Structure and Grammar — Design

Status: approved in conversation, 2026-10-08 ("Keep going." after stage 1; stage list in
`docs/superpowers/specs/2026-10-08-lean-formalization-brief.md` §1).

## 1. Brief

**You said.** Continue with the next stage: a parser from configuration text to an AST,
tested against the `rules:` block of every engine profile, including the `expect_error`
ones.

**Agreed.** `formal/` gains a lexer and parser for `spec/01-lexical.md` and
`spec/02-grammar.md`, with the directive table of `spec/04-directives.md` (name, status,
argument shape) and the name tables of chapters 05–08 (variables, operators, actions, `ctl`
options, transformations) as the vocabulary. A second executable, `lake exe seclang-parse`,
loads the configuration of every engine profile and reports whether the model accepts or
rejects it; a profile whose stages carry `expect_error: true` MUST be rejected, every other
profile MUST be accepted. The YAML is read by a small Python extractor so the Lean side
stays dependency-free. Every disagreement between prose, corpus and engines is fixed in
the branch as before.

**Assumptions.**

- The model implements every "MUST be a configuration error" of chapters 01–04 that is
  decidable from the configuration text alone, plus the operator-parameter rules chapter
  06 states as configuration errors (`@ipMatch` entries, `@validateByteRange` ranges).
  Operator parameters are otherwise opaque text; regular expressions are not compiled
  (ADR-0018 defers the regex dialect).
- Per ADR-0005, a directive that is Engine-specific is "not defined" for the model, which
  is no engine, and is rejected; the same reading applies to operator, action, `ctl`
  option and variable names, which chapters 06, 08 and 05 list as reserved.
- The shapes "collection" or "scalar" needed for the selector rule are taken from each
  Core variable's semantics sentence; Extended and Deprecated variables are not declared
  either way in `spec/05-variables.md`, so the model does not enforce the rule for them.
- `Include` resolves a relative path against the profile's auxiliary `files:` map, as
  both adapters do; a single `*` is the only glob form; a non-glob path that does not
  exist and a glob that matches nothing are errors (v2 and v3 agree on the latter; the
  prose leaves it unspecified).

## 2. Shape

```
tools/engine_rules.py                 tests/engine/**/*.yaml → JSON [{path, rules, files, expect_error}] on stdout
tools/test_engine_rules.py            extractor unit test
formal/SecLang/Names.lean             vocabulary tables: directives (status, argument shape), variables (status, shape),
                                      operators (status, aliases), actions (status, value kind, class), ctl options,
                                      transformations (status, aliases); case-insensitive lookup
formal/SecLang/Syntax.lean            AST; lexer (lines, continuation, comments, arguments); directive parser
                                      (variable list, operator, action list, ranges, parts); configuration checks
                                      (ids, chains, default actions, Include)
formal/ParseMain.lean                 lake exe seclang-parse <engine-rules.json>
formal/lakefile.toml                  second lean_exe
```

## 3. The model

**Lexer** (`01-lexical.md`). Input bytes. Lines split on LF, a trailing CR dropped. A
physical line whose last non-blank byte is `\` joins the next one with the backslash and
the break removed and all other whitespace kept, before comment detection (ADR-0013). A
logical line whose first non-blank byte is `#`, or that is blank, is dropped. The rest is
a directive: a name and arguments split on runs of space or tab; a `"`-delimited argument
keeps whitespace, `\"` yields `"`, any other backslash pair is passed through unchanged
(`\\` is left as two bytes, the v3 and Coraza reading of an unspecified point); an
unterminated quote or a byte directly after a closing quote is an error. Every logical
line carries its first physical line number for error messages.

**Vocabulary** (`Names.lean`). One table per chapter, each row a canonical name, its
status, and what the parser needs: for directives the argument shape (`none`, `one`
of a kind, `oneOrMore`, `actions`, `idRanges`, `idRangesThenArgument`, `regexThenArgument`,
`rule`), with kinds `onOff`, `onOffDetectionOnly`, `onOffRelevantOnly`,
`rejectProcessPartial`, `nativeJson`, `serialConcurrent`, `nat`, `octal`, `auditParts`,
`text`; for actions the value kind (`none`, `id`, `phase`, `severity`, `nat`,
`transformation`, `ctl`, `setvar`, `label`, `text`, `allow`) and the class (`disruptive`,
`metadata`, `flow`, `other`); for variables the shape (`collection`, `scalar`,
`unspecified`). Lookups lower-case both sides (ADR-0002); aliases from ADR-0004 resolve
to their canonical row. A name whose status is Engine-specific is not found.

**Parser** (`02-grammar.md`, `04-directives.md`). Arity and argument kinds from the
directive row. `SecRule`: variable list, operator, optional action list; `SecAction`:
action list. Variable list split on `|`; each entry an optional `!` or `&`, a known
collection name, an optional `:` selector that is `/…/` (closed), a key with no `|` or
whitespace, or for `XML` any XPath text; a selector on a scalar is an error. Operator:
optional `!`, `@name` and parameter after one run of whitespace, or the implicit `@rx`
parameter; the name must be known; `@ipMatch` entries must parse as IPv4/IPv6 with an
optional prefix in range; `@validateByteRange` must be comma-separated decimal bytes or
`LOW-HIGH` with both in 0–255. Action list split on commas outside `'…'` with `\'` a
literal quote, names trimmed and known, values checked by kind (`id` a positive integer,
optionally quoted; `phase` 1–5 or a phase name; `severity` 0–7 or a level name, optionally
quoted; `status` a number; `t:` a known transformation; `ctl:` a known option with its value
form; `setvar:` one of the five forms). Rules: at most one disruptive action; a rule that is
not a chain member carries an `id`; a chain member carries no `id`, `phase`, metadata or
disruptive action; ids unique across the configuration including included files.
`SecDefaultAction`: a `phase`, exactly one disruptive action, none of `chain`, `skip`,
`skipAfter`, `t:` or metadata, at most one per phase. `SecRuleRemoveById` and friends:
ids or `A-B` ranges with `A <= B`; `TARGETS` parsed as a variable list (a leading `!`
allowed); `ACTIONS` as an action list. `SecAuditLogParts`: letters in `A`–`K` and `Z`
only. `Include`: the file's lines are parsed in place with their own line numbers.

**AST.** `Config` is the list of directives in order with `Include` expanded; a
`Rule` has variables, operator, actions and the resolved chain membership. Stage 3 will
consume this AST.

**Runner.** `lake exe seclang-parse FILE` reads the extractor's JSON and prints one line
per profile: `path: accepted` or `path: rejected: <line>: <message>`, then
`N profiles, M mismatches`; a mismatch is a profile accepted when `expect_error` is set or
rejected when it is not, and makes the exit status 1.

## 4. What the model forces into the spec

Known before implementation:

- `02-grammar.md#variable-selectors`: the `selector` rule has no production for the
  `XML` collection, whose selectors are XPath expressions (`XML://@*` in the corpus).
  The EBNF and the prose get an `XML` exception pointing at `05-variables.md#xml`.
- `02-grammar.md#variable-list`: the prose never says what an unknown collection name is;
  chapters 06 and 08 say it for operators and actions. The same sentence is added for
  variables (ADR-0005's reading: a name this specification does not define is a
  configuration error; Engine-specific names are reserved, not defined).

Any further disagreement the first run surfaces is classified per `AGENTS.md`: spec defect
(fix the text), profile defect (fix the profile and rerun the Coraza adapter), model
defect (fix the Lean).

## 5. Repository integration

- `.github/workflows/validate.yml`: the `lean` job installs `uv`, runs the extractor into
  `formal/.lake/engine-rules.json` and `lake exe seclang-parse` on it after
  `seclang-check`.
- `AGENTS.md`, `README.md`, `formal/README.md`: the `formal/` entries name both
  executables and the extractor.
- `tools/validate.py`: unchanged.

## 6. Verdict criteria

Every one of the 102 profiles is classified as the corpus expects (93 accepted, 9
rejected with a message naming the spec rule), `lake build` evaluates every guard,
validator and tools tests pass, the Coraza adapter stays green, and the two spec fixes in
§4 plus anything the run surfaced are in the text.
