# Known conformance gaps

Core tests in `tests/` that a surveyed engine is known to fail today, with the spec
section that decides the behaviour. An entry here is a bug for the engine, not a
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
| `tests/engine/processing/skipafter-later-phase.yaml` | libmodsecurity v3, Coraza | unreached `skipAfter` continues into later phases | ADR-0016 |
| `tests/engine/processing/rule-exceptions-bad-range.yaml` | ModSecurity v2 | `200-100` accepted silently | `03-processing-model.md#rule-exceptions` |
| `tests/engine/processing/rule-exceptions-unknown-id.yaml` | Coraza | `SecRuleUpdateTargetById` with an unknown id is an error | `03-processing-model.md#rule-exceptions` |
| `tests/engine/directives/secargumentseparator.yaml` | Coraza | directive parsed and ignored | `04-directives.md#secargumentseparator`, ADR-0005 |
| `tests/engine/directives/deprecated-directive-accepted.yaml` | none | `SecHashEngine Off` is accepted everywhere; see ADR-0005 for the Deprecated names v3 and Coraza reject | ADR-0005 |
| `tests/unit/operators/ipMatch.json` | Coraza | `::ffff:ffff:ffff` does not match `0:0::/80` (one case) | `06-operators.md#ipmatch` |
| `tests/unit/transformations/uppercase-extra.json` | ModSecurity v2 | `t:uppercase` not implemented | ADR-0012 |
| `tests/unit/transformations/cssDecode.json` | Coraza | six-digit escapes above U+FFFF decode to U+FFFD (two cases) | `07-transformations.md#cssdecode` |
| `tests/unit/transformations/urlDecodeUni.json` | Coraza | one full-width `%u` case decodes differently | `07-transformations.md#urldecodeuni` |
| `tests/engine/variables/key-case.yaml` | Coraza (`coraza.rule.case_sensitive_args_keys` build only) | `ARGS` keys compared exactly | ADR-0008 |

Not listed: differences the specification leaves unspecified (defaults, status codes,
empty `Include` globs), since no test asserts on them.
