# 04. Directives

One section per directive. Phase 1 contains the single worked example; the remaining
Core directives arrive in Phase 2.

### SecRuleEngine

**Status:** Core

**Syntax.** `SecRuleEngine On|Off|DetectionOnly`

**Default.** `Off` in ModSecurity v2 and Coraza. libmodsecurity v3 has no engine-level
default: the connector supplies one. Rulesets MUST set it explicitly.

**Scope.** Main configuration and any included file. The last occurrence before a
transaction starts wins. `ctl:ruleEngine` changes the value for the current
transaction only.

**Semantics.**

- `On`: rules are evaluated and disruptive actions (`deny`, `drop`, `redirect`,
  `allow`) take effect.
- `DetectionOnly`: rules are evaluated, matches are logged, variables are set, but no
  disruptive action interrupts the transaction. The status code of the transaction is
  unaffected.
- `Off`: no rules are evaluated. Nothing is logged by rules. Request and response body
  handling directives still apply where the engine needs them for other purposes.

**Divergence notes.** None known for the three values. Engines differ on the default;
this specification does not standardize the default because every published ruleset
sets it.

**Tests.** `tests/engine/directives/secruleengine-on.yaml`,
`tests/engine/directives/secruleengine-detectiononly.yaml`,
`tests/engine/directives/secruleengine-off.yaml`
