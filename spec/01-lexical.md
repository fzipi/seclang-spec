# 01. Lexical structure

This file will grow to cover lines, continuation, quoting, comments and `Include`
(design Section 4.3). Phase 1 defines only the section ADR-0002 depends on.

### Name matching

**Status:** Core

**Syntax.** Directive names (`SecRule`), operator names (`@contains`), action names
(`deny`, `t:`), transformation names (`lowercase`) and `ctl:` option names
(`ruleEngine`) are identifiers made of ASCII letters and digits.

**Semantics.** Engines MUST match all of these identifiers case-insensitively.
`secrule`, `SecRule` and `SECRULE` denote the same directive; `@CONTAINS` and
`@contains` the same operator; `T:LOWERCASE` and `t:lowercase` the same
transformation. The canonical spelling used in this specification is the mixed-case
form from the ModSecurity reference manual; engines SHOULD emit that spelling in logs
and error messages.

Variable and collection names (`ARGS`, `TX`) and collection keys are **not** covered by
this section; their case rules are defined with the variables (ADR-0008, Phase 3).

**Divergence notes.** ModSecurity v2 and v3 already behave this way. Coraza 3.8.1
matches directive, action and transformation names case-insensitively but operator
names case-sensitively. See ADR-0002.

**Tests.** `tests/engine/lexical/case-insensitive-names.yaml`
