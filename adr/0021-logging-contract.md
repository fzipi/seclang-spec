# ADR-0021: The portable logging contract is rule ids and messages

- **Status:** proposed
- **Date:** 2026-10-07
- **Deciders:** @fzipi
- **Category:** Clarification

## Context

The engines agree on almost nothing in their log output beyond structure:

- Error log prefixes: `ModSecurity: Warning.` / `ModSecurity: Access denied with code N`
  (v2 `apache2/mod_security2.c`, v3 `src/rule_message.cc`) versus `Coraza: Warning.` /
  `Coraza: Access denied (phase N).` (`internal/corazarules/rule_match.go`). The bracketed
  fields `[id "…"]` and `[msg "…"]` appear in all three.
- Audit log JSON: v2, v3 and Coraza each have their own object layout; Coraza adds
  `jsonlegacy` and `ocsf`.
- Audit log parts: Coraza does not fill `D`, `E`, `G`; stopwatch and producer lines
  differ.
- Debug log: free text in ModSecurity, a structured logger in Coraza.

The design document (section 4.4) already excludes log layout from the test tiers:
"Logging tests assert only on rule IDs and `msg` presence."

## Decision

Normative logging behaviour is limited to: one error-log line per logged match carrying
`[id "N"]` and, when present, `[msg "TEXT"]`, suppressed by `nolog`; audit-log relevance
rules; the set of audit parts with the minimum content of `A`, `B`, `F`, `H`, `Z`; and the
Native format's part-marker structure. The JSON audit format is Extended with an
unspecified shape; the debug log is Extended with unspecified wording. Engine-tier
profiles use `log_contains`/`no_log_contains` only with `msg` text.

## Options considered

- Specify ModSecurity's layout as Core: would make Coraza non-conforming for cosmetic
  reasons and freeze a format that log collectors already parse per engine; rejected.
- Specify nothing about logs: rules such as CRS's anomaly reporting rely on `msg` reaching
  the log, and adapters need a definition of `log_contains`; rejected.
- Minimum contract (chosen).

## Consequences

- For engines: none today; all three satisfy the contract.
- For adapters: implement `log_contains` over the error log or the engine's matched-rule
  messages.
- For log consumers: continue to parse per engine; a shared JSON schema is future work.

## Tests

- `tests/engine/logging/error-log-fields.yaml`
- `tests/engine/logging/audit-relevance-load.yaml`

## References

- `spec/10-logging.md`, `tests/README.md`
