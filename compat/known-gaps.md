# Known conformance gaps

Core tests in `tests/` that a surveyed engine is known to fail today, with the spec
section that decides the behaviour. The engines are ModSecurity v2 (`v2/master`,
2026-09), libmodsecurity v3.0.16 and Coraza v3.8.1, as read from source on 2026-10-06
and 2026-10-07. Rows naming Coraza are **verified**: `adapters/coraza` runs every test
in CI and fails when a listed file passes or an unlisted one fails. Rows naming only the
ModSecurity branches remain predictions from source until an adapter exists for them. An entry here is a bug for the engine, not a
weakness of the test. Entries are removed when the engine is fixed; new ones are added
whenever a Divergence ADR or a divergence note picks against an engine.

| Test | Engine | Behaviour today | Decided in |
|---|---|---|---|
| `tests/engine/lexical/case-insensitive-names.yaml` | Coraza | operator names matched case-sensitively | ADR-0002 |
| `tests/engine/lexical/comment-with-trailing-backslash.yaml` | Coraza | continued comment parsed as a directive | ADR-0013 |
| `tests/engine/grammar/directive-line-whitespace.yaml` | Coraza | tab between arguments is a load error | `02-grammar.md#directive-line` |
| `tests/engine/grammar/secrule-requires-id.yaml` | Coraza | rule without `id` loads (default build) | ADR-0015 |
| `tests/engine/processing/default-phase.yaml` | libmodsecurity v3 | phase-less rule runs in phase 1 | ADR-0017 |
| `tests/engine/processing/default-action-no-phase.yaml` | libmodsecurity v3 | missing phase defaults to 1 | ADR-0014 |
| `tests/engine/processing/default-action-redefined.yaml` | ModSecurity v2 | second `SecDefaultAction` replaces the first | ADR-0014 |
| `tests/engine/processing/skipafter-missing-marker.yaml` | libmodsecurity v3, Coraza | `skipAfter` naming a marker that does not exist disables every later phase | ADR-0016 |
| `tests/engine/processing/rule-exceptions-bad-range.yaml` | ModSecurity v2 | `200-100` accepted silently | `03-processing-model.md#rule-exceptions` |
| `tests/engine/processing/rule-exceptions-unknown-id.yaml` | Coraza | `SecRuleUpdateTargetById` with an unknown id is an error | `03-processing-model.md#rule-exceptions` |
| `tests/engine/actions/setvar.yaml` | Coraza | any `setvar` without `=value` (`setvar:tx.x`, `setvar:!tx.x`) dereferences a nil macro and panics (`internal/actions/setvar.go` `Evaluate`) | `08-actions.md#setvar` |
| `tests/engine/lexical/quoted-arguments.yaml` | libmodsecurity v3 | `\"` inside an operator argument keeps its backslash (prediction from `seclang-scanner.ll`) | `01-lexical.md#quoting-and-escapes` |
| `tests/engine/directives/secargumentseparator.yaml` | Coraza | directive parsed and ignored | `04-directives.md#secargumentseparator`, ADR-0005 |
| `tests/engine/directives/deprecated-directive-accepted.yaml` | none | `SecHashEngine Off` is accepted everywhere; see ADR-0005 for the Deprecated names v3 and Coraza reject | ADR-0005 |
| `tests/unit/operators/ipMatch.json` | Coraza | `::ffff:ffff:ffff` does not match `0:0::/80` (one case) | `06-operators.md#ipmatch` |
| `tests/unit/transformations/uppercase-extra.json` | ModSecurity v2 | `t:uppercase` not implemented | ADR-0012 |
| `tests/unit/transformations/cssDecode.json` | Coraza | six-digit escapes above U+FFFF decode to U+FFFD (two cases) | `07-transformations.md#cssdecode` |
| `tests/unit/transformations/urlDecodeUni.json` | Coraza | one full-width `%u` case decodes differently | `07-transformations.md#urldecodeuni` |
| `tests/engine/actions/allow.yaml` | Coraza | `allow` also skips the logging phase | `08-actions.md#allow` |
| `tests/unit/transformations/htmlEntityDecode.json` | Coraza | `&nbsp;` decodes to UTF-8 `C2 A0` (two cases) | `07-transformations.md#htmlentitydecode` |
| `tests/engine/body/no-processor.yaml`, `tests/engine/actions/ctl-options.yaml` | libmodsecurity v3 | `ctl:forceRequestBodyVariable` parsed but not implemented | ADR-0022 |
| `tests/engine/variables/multipart.yaml` | Coraza | `FILES` members keyed by the empty string, so `FILES:field` selects nothing | `05-variables.md#files` |
| `tests/unit/operators/beginsWith.json`, `tests/unit/operators/contains.json`, `tests/unit/operators/endsWith.json`, `tests/unit/operators/streq.json`, `tests/unit/operators/within.json` | Coraza | an empty operator parameter is a load error ("empty data"); the spec says an empty string matches every value (one case per file) | `06-operators.md#contains` |
| `tests/unit/transformations/hexDecode.json` | Coraza | input with an odd length or a non-hex character is returned unchanged instead of decoding the valid pairs (three cases) | `07-transformations.md#hexdecode` |

## Divergences no test can observe

Recorded here so they are not lost; they are not rows above because the adapters would
otherwise report them as obsolete.

- Coraza marks a transaction audit-relevant only when a rule carried `auditlog`
  explicitly, and when `SecAuditLogRelevantStatus` is set it also requires the status to
  match (`10-logging.md#audit-log-relevance`).
- Coraza built with `coraza.rule.case_sensitive_args_keys` compares `ARGS` keys exactly
  (ADR-0008); the default build conforms.
- Coraza calls its error-log callback only for rules carrying `log` explicitly; ModSecurity
  logs by default (`08-actions.md#log`).

Not listed: differences the specification leaves unspecified (defaults, status codes,
empty `Include` globs), since no test asserts on them.
