# ADR-0014: `SecDefaultAction` constraints

- **Status:** proposed
- **Date:** 2026-10-06
- **Deciders:** @fzipi
- **Category:** Divergence

## Context

- ModSecurity v2 (`apache2/apache2_config.c`, `cmd_default_action`) rejects a
  `SecDefaultAction` that lacks a disruptive action or a phase, or that contains
  `chain`, `skip`, `skipAfter` or any metadata action (`id`, `rev`, `msg`, `tag`,
  `severity`, `ver`, `accuracy`, `maturity`, `logdata`); it warns on `severity`,
  `logdata` and transformations. A later `SecDefaultAction` for the same phase replaces
  the earlier one for subsequent rules.
- libmodsecurity v3 (`src/parser/seclang-parser.yy`) rejects a missing disruptive action
  and any action that is not evaluated at run time (`not suitable to be part of the
  SecDefaultActions`), rejects `t:none`, defaults a missing phase to 1, and rejects a
  second `SecDefaultAction` for the same phase in one context (`can only be placed once
  per phase and configuration context`).
- Coraza 3.8.1 (`internal/seclang/directives.go`, `directiveSecDefaultAction`) performs
  no validation, appends every `SecDefaultAction` to a list, and applies a built-in
  `phase:2,log,auditlog,pass` when none is configured.

## Decision

A `SecDefaultAction` MUST contain a `phase` and exactly one disruptive action, and MUST
NOT contain `chain`, `skip`, `skipAfter`, `t:none` or the metadata actions `id`, `rev`,
`msg`, `tag`, `severity`, `ver`, `accuracy`, `maturity`, `logdata`. A violating directive
MUST be a configuration error. A later `SecDefaultAction` for the same phase replaces the
earlier one for the rules that follow it. Normative text: `spec/03-processing-model.md
#default-actions`.

## Options considered

- Coraza's leniency: a `SecDefaultAction "log"` silently does nothing useful, and a
  `tag:` in it would be inherited by every rule, which CRS tooling does not expect;
  rejected.
- v3's once-per-phase rule: stricter than v2 and the reference manual, and would break
  configurations that re-set the default action in a later file; rejected for Core,
  recorded as a v3 divergence.
- v2's rules with replacement semantics (chosen): the documented behaviour since
  ModSecurity 2.x.

## Consequences

- For ModSecurity v2: no change.
- For libmodsecurity v3: require a phase instead of defaulting it; allow redefinition
  per phase.
- For Coraza: validate the action list as above.
- For rule authors: `SecDefaultAction "phase:N,log,auditlog,pass"` as CRS ships it is
  valid everywhere.

## Tests

- `tests/engine/processing/default-action-no-phase.yaml`
- `tests/engine/processing/default-action-no-disruptive.yaml`
- `tests/engine/processing/default-action-redefined.yaml`

## References

- `spec/03-processing-model.md#default-actions`, `spec/04-directives.md#secdefaultaction`
