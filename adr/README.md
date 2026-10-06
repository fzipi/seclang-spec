# Architecture Decision Records

An ADR records a decision about the SecLang specification: what was decided, which
alternatives existed, and why. Write one whenever the engines disagree and the spec
has to pick (Divergence), when behaviour is undocumented but agreed (Clarification),
when a legacy feature is retired (Deprecation), or when an engine-specific feature is
promoted into the spec (Extension).

## Process

1. Copy `0000-template.md` to `NNNN-short-slug.md` with the next free number.
2. Fill every header field. `Status` is `proposed` until maintainers of at least two
   implementing engines agree, then `accepted`. `superseded` and `rejected` are terminal.
3. A `Divergence` ADR must list at least one test under `## Tests` that encodes the
   outcome. The validator checks the paths exist.
4. Add a row to the index below. `uv run python tools/validate.py` fails if a file and the
   index disagree.
5. Update the affected section of `spec/` in the same PR.

Numbers 0007–0012 are reserved for the decisions listed in the design document
(persistent collections, `ARGS` key case, phase model, engine extensions, v2 legacy,
`uppercase`) and will be written in Phase 3.

## Index

| ADR | Title | Category | Status |
|---|---|---|---|
| [0001](0001-status-labels-and-core.md) | Status labels and the meaning of Core | Clarification | proposed |
| [0002](0002-case-insensitive-names.md) | Directive, operator, action and transformation names match case-insensitively | Divergence | proposed |
| [0003](0003-test-formats.md) | Test formats: SecRules Test Set JSON for units, go-ftw-derived YAML for engine profiles | Clarification | proposed |
| [0004](0004-canonical-names-and-aliases.md) | Canonical names and required aliases | Divergence | proposed |
| [0005](0005-unknown-and-unsupported-directives.md) | Unknown versus unsupported directives | Divergence | proposed |
| [0006](0006-core-ctl-options.md) | Core `ctl:` options | Divergence | proposed |
| [0013](0013-comment-line-continuation.md) | Comment lines ending in a backslash | Divergence | proposed |
| [0014](0014-secdefaultaction-constraints.md) | `SecDefaultAction` constraints | Divergence | proposed |
| [0015](0015-mandatory-rule-id.md) | Every rule carries an id | Divergence | proposed |
| [0016](0016-skipafter-scope.md) | `skipAfter` scope ends with the phase | Divergence | proposed |
