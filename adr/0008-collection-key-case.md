# ADR-0008: Collection keys match case-insensitively

- **Status:** proposed
- **Date:** 2026-10-06
- **Deciders:** @fzipi
- **Category:** Divergence

## Context

- ModSecurity v2 compares a selector against member names with `strcasecmp`
  (`apache2/re_variables.c`, every `var_*_generate` for `ARGS`, `REQUEST_HEADERS`,
  `REQUEST_COOKIES`, `TX`, …).
- libmodsecurity v3 stores members in an unordered multimap with a lower-casing hash and
  equality (`headers/modsecurity/anchored_set_variable.h`, `MyHash`, `MyEqual`).
- Coraza 3.8.1 lower-cases keys on storage and lookup (`internal/collections/map.go`)
  unless built with `coraza.rule.case_sensitive_args_keys` (Coraza ADR-0016), in which case
  `ARGS` keys are compared exactly; Coraza ADR-0015 added a case-sensitive map type for
  internal use and deferred switching the default to v4.

OWASP CRS writes `%{tx.anomaly_score}` and `TX:ANOMALY_SCORE` interchangeably (hundreds of
occurrences of each spelling) and selects headers as `REQUEST_HEADERS:Content-Type`.

## Decision

Member names in every collection are matched against key selectors, macro keys and
`setvar` names case-insensitively. A regex selector is applied to the member name as the
engine parsed it and is case-sensitive unless the expression says otherwise. Normative
text: `spec/05-variables.md#collection-keys`. The Coraza case-sensitive build is
non-conforming.

## Options considered

- Case-sensitive keys: HTTP header names are case-insensitive by RFC 9110 and CRS mixes
  `TX` key spellings; rejected.
- Per-collection sensitivity (Coraza's own stated ideal): no engine implements it and no
  ruleset needs it; rejected for now.
- Case-insensitive everywhere (chosen).

## Consequences

- For ModSecurity: no change.
- For Coraza: keep the default; the build tag stays opt-in and documented as
  non-conforming.
- For rule authors: argument names that differ only in case cannot be distinguished by a
  key selector; use a regex selector if that ever matters.

## Tests

- `tests/engine/variables/key-case.yaml`

## References

- `spec/05-variables.md#collection-keys`
- Coraza ADR-0015 and Coraza ADR-0016 in `corazawaf/coraza/docs/adr`
