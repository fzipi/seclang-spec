# ADR-0019: `DURATION` is Extended with unspecified units

- **Status:** proposed
- **Date:** 2026-10-06
- **Deciders:** @fzipi
- **Category:** Clarification

## Context

All three engines expose a `DURATION` variable with three incompatible meanings:

- ModSecurity v2: wall-clock microseconds since the request started
  (`apache2/re_variables.c`, `apr_time_now() - msr->r->request_time`).
- libmodsecurity v3: process CPU seconds since the transaction was created, as a decimal
  fraction (`src/variables/duration.cc`, `utils::cpu_seconds()`).
- Coraza 3.8.1: the constant `"0"` (`internal/corazawaf/waf.go`).

The reference manual says "milliseconds". No published ruleset reads it.

## Decision

`DURATION` is Extended. Its unit and clock are unspecified; a new implementation SHOULD
report wall-clock milliseconds as the manual says, and engines SHOULD document what they
do report. No test asserts on its value.

## Options considered

- Standardise on milliseconds and make it Core: every engine would be non-conforming;
  rejected.
- Deprecate: it is cheap to implement correctly and useful for slow-request rules;
  rejected.

## Consequences

- For rule authors: do not compare `DURATION` across engines.

## Tests

None.

## References

- `spec/05-variables.md#duration`
