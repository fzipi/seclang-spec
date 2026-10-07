# ADR-0025: `SecRequestBodyInMemoryLimit` is Extended, not Core

- **Status:** proposed
- **Date:** 2026-10-07
- **Deciders:** @fzipi
- **Category:** Divergence

## Context

Draft 0.1 listed `SecRequestBodyInMemoryLimit` as Core with all three engines marked as
implementing it. The libmodsecurity reference adapter showed that v3.0.16 rejects the
directive at load time ("As of ModSecurity version 3.0, SecRequestBodyInMemoryLimit is no
longer supported", `src/parser/seclang-parser.yy`): the web server, not the library,
decides how a body is buffered. ModSecurity v2 (`apache2/msc_reqbody.c`) and Coraza
(`internal/corazawaf/body_buffer.go`, `coraza.conf-recommended`) implement it as the
threshold above which the body is spooled to a temporary file. The directive never
affects rule evaluation. Demoting from Core requires an ADR (`spec/00-conventions.md`).

## Decision

`SecRequestBodyInMemoryLimit` is **Extended**: engines that buffer request bodies
themselves SHOULD implement it; an engine that delegates buffering to its host MAY
reject it. Profiles that use it declare
`requires: [04-directives.md#secrequestbodyinmemorylimit]` so adapters for engines
without it skip them. Normative text: `spec/04-directives.md#secrequestbodyinmemorylimit`.

## Options considered

- Keep Core with a known-gaps row for v3: makes a deliberate v3 design choice a
  permanent "bug"; rejected.
- Deprecated: wrong signal, since two conforming engines implement and recommend it;
  rejected.
- Extended (chosen): matches the definitions in `spec/00-conventions.md` (implemented by
  some engines, not required for conformance).

## Consequences

- For libmodsecurity v3: no change; the matrix lists the directive absent.
- For rule authors: a shared configuration that sets it does not load on libmodsecurity
  v3 unless the line is removed or kept in a v2/Coraza-specific include.
- `tests/engine/directives/body-limit-directives-load.yaml` no longer sets it; the
  Extended profile below carries it.

## Tests

- `tests/engine/directives/secrequestbodyinmemorylimit.yaml`

## References

- `spec/04-directives.md#secrequestbodyinmemorylimit`, `spec/00-conventions.md`
- `adapters/libmodsecurity/README.md`
