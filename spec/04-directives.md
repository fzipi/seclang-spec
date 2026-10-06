# 04. Directives

One section per directive. Sections are grouped by purpose; the index below lists every
directive name known to any surveyed engine, with its status (`00-conventions.md`) and
which engines accept the name at all (`compat/matrix.md`). Accepting a name is not
implementing it: Coraza, for example, parses and ignores several directives, which is
why `04-directives.md` and ADR-0005 distinguish the two.

Defaults are listed per engine. A default is normative only when the three engines
agree; otherwise it is left unspecified and portable configurations set the directive
explicitly, as both engines' recommended configuration files do.

## Index

| Directive | Status | v2 | v3 | Coraza | Purpose |
|---|---|---|---|---|---|
| [Include](#include) | Core | yes | yes | yes | Parse another configuration file in place |
| [SecAction](#secaction) | Core | yes | yes | yes | Unconditional rule |
| [SecArgumentSeparator](#secargumentseparator) | Core | yes | yes | yes | Character separating urlencoded arguments |
| [SecArgumentsLimit](#secargumentslimit) | Core | yes | yes | yes | Maximum number of arguments parsed |
| [SecAuditEngine](#secauditengine) | Core | yes | yes | yes | Audit logging mode |
| [SecAuditLog](#secauditlog) | Core | yes | yes | yes | Audit log destination |
| [SecAuditLog2](#secauditlog2) | Deprecated | yes | yes | - | Secondary audit log destination |
| [SecAuditLogDirMode](#secauditlogdirmode) | Extended | yes | yes | yes | Permissions of created audit directories |
| [SecAuditLogFileMode](#secauditlogfilemode) | Extended | yes | yes | yes | Permissions of created audit files |
| [SecAuditLogFormat](#secauditlogformat) | Core | yes | yes | yes | Audit log serialization format |
| [SecAuditLogParts](#secauditlogparts) | Core | yes | yes | yes | Which parts an audit entry contains |
| [SecAuditLogPrefix](#secauditlogprefix) | Engine-specific | - | yes | - | Prefix for concurrent audit file names |
| [SecAuditLogRelevantStatus](#secauditlogrelevantstatus) | Core | yes | yes | yes | Status regex selecting relevant transactions |
| [SecAuditLogStorageDir](#secauditlogstoragedir) | Core | yes | yes | yes | Directory for concurrent audit files |
| [SecAuditLogType](#secauditlogtype) | Core | yes | yes | yes | Serial or concurrent audit logging |
| [SecCacheTransformations](#seccachetransformations) | Deprecated | yes | yes | - | Cache transformation results |
| [SecChrootDir](#secchrootdir) | Deprecated | yes | yes | - | Chroot the server process |
| [SecCollectionTimeout](#seccollectiontimeout) | Extended | yes | yes | yes | Expiry of persistent collections |
| [SecComponentSignature](#seccomponentsignature) | Core | yes | yes | yes | Append a component to the engine signature |
| [SecConnEngine](#secconnengine) | Deprecated | yes | yes | yes | Connection limiting engine |
| [SecConnReadStateLimit](#secconnreadstatelimit) | Deprecated | yes | yes | yes | Max connections in read state per IP |
| [SecConnWriteStateLimit](#secconnwritestatelimit) | Deprecated | yes | yes | yes | Max connections in write state per IP |
| [SecContentInjection](#seccontentinjection) | Deprecated | yes | yes | - | Enable append/prepend |
| [SecCookieFormat](#seccookieformat) | Extended | yes | yes | yes | Cookie parsing version |
| [SecCookieV0Separator](#seccookiev0separator) | Extended | yes | yes | - | Separator for version 0 cookies |
| [SecDataDir](#secdatadir) | Core | yes | yes | yes | Directory for persistent storage |
| [SecDataset](#secdataset) | Engine-specific | - | - | yes | Inline dataset for @pmFromDataset/@ipMatchFromDataset |
| [SecDebugLog](#secdebuglog) | Core | yes | yes | yes | Debug log destination |
| [SecDebugLogLevel](#secdebugloglevel) | Core | yes | yes | yes | Debug log verbosity |
| [SecDefaultAction](#secdefaultaction) | Core | yes | yes | yes | Default action list per phase |
| [SecDisableBackendCompression](#secdisablebackendcompression) | Deprecated | yes | yes | - | Strip Accept-Encoding toward the backend |
| [SecGeoLookupDb](#secgeolookupdb) | Extended | yes | yes | - | GeoIP database path |
| [SecGsbLookupDb](#secgsblookupdb) | Deprecated | yes | yes | yes | Google Safe Browsing database |
| [SecGuardianLog](#secguardianlog) | Deprecated | yes | yes | - | Pipe to the httpd-guardian script |
| [SecHashEngine](#sechashengine) | Deprecated | yes | yes | yes | Hash engine (link integrity) |
| [SecHashKey](#sechashkey) | Deprecated | yes | yes | yes | Hash engine key |
| [SecHashMethodPm](#sechashmethodpm) | Deprecated | yes | yes | yes | Hash engine phrase matching |
| [SecHashMethodRx](#sechashmethodrx) | Deprecated | yes | yes | yes | Hash engine regex matching |
| [SecHashParam](#sechashparam) | Deprecated | yes | yes | yes | Hash engine parameter name |
| [SecHttpBlKey](#sechttpblkey) | Extended | yes | yes | yes | Project Honey Pot key for @rbl |
| [SecIgnoreRuleCompilationErrors](#secignorerulecompilationerrors) | Engine-specific | - | - | yes | Continue loading after a rule error |
| [SecInterceptOnError](#secinterceptonerror) | Deprecated | yes | yes | - | Intercept on processing errors |
| [SecMarker](#secmarker) | Core | yes | yes | yes | Named target for skipAfter |
| [SecParseXmlIntoArgs](#secparsexmlintoargs) | Extended | yes | yes | - | Expose XML content as ARGS |
| [SecPcreMatchLimit](#secpcrematchlimit) | Extended | yes | yes | yes | PCRE match limit |
| [SecPcreMatchLimitRecursion](#secpcrematchlimitrecursion) | Extended | yes | yes | yes | PCRE recursion limit |
| [SecReadStateLimit](#secreadstatelimit) | Deprecated | yes | - | - | Older name of SecConnReadStateLimit |
| [SecRemoteRules](#secremoterules) | Extended | yes | yes | yes | Load rules from a URL |
| [SecRemoteRulesFailAction](#secremoterulesfailaction) | Extended | yes | yes | yes | Behaviour when remote rules fail to load |
| [SecRequestBodyAccess](#secrequestbodyaccess) | Core | yes | yes | yes | Buffer and inspect request bodies |
| [SecRequestBodyInMemoryLimit](#secrequestbodyinmemorylimit) | Core | yes | yes | yes | Memory buffer size before spooling to disk |
| [SecRequestBodyJsonDepthLimit](#secrequestbodyjsondepthlimit) | Core | yes | yes | yes | Maximum JSON nesting depth |
| [SecRequestBodyLimit](#secrequestbodylimit) | Core | yes | yes | yes | Maximum request body size |
| [SecRequestBodyLimitAction](#secrequestbodylimitaction) | Core | yes | yes | yes | What to do above the limit |
| [SecRequestBodyNoFilesLimit](#secrequestbodynofileslimit) | Core | yes | yes | yes | Maximum request body size excluding files |
| [SecRequestEncoding](#secrequestencoding) | Deprecated | yes | - | - | Declared request character encoding |
| [SecResponseBodyAccess](#secresponsebodyaccess) | Core | yes | yes | yes | Buffer and inspect response bodies |
| [SecResponseBodyJsonDepthLimit](#secresponsebodyjsondepthlimit) | Engine-specific | - | - | yes | Maximum response JSON nesting depth |
| [SecResponseBodyLimit](#secresponsebodylimit) | Core | yes | yes | yes | Maximum response body size |
| [SecResponseBodyLimitAction](#secresponsebodylimitaction) | Core | yes | yes | yes | What to do above the limit |
| [SecResponseBodyMimeType](#secresponsebodymimetype) | Core | yes | yes | yes | Response types to inspect |
| [SecResponseBodyMimeTypesClear](#secresponsebodymimetypesclear) | Core | yes | yes | yes | Reset the inspected type list |
| [SecRule](#secrule) | Core | yes | yes | yes | Conditional rule |
| [SecRuleEngine](#secruleengine) | Core | yes | yes | yes | Rule processing mode |
| [SecRuleInheritance](#secruleinheritance) | Extended | yes | yes | - | Inherit rules into child contexts |
| [SecRulePerfTime](#secruleperftime) | Extended | yes | yes | yes | Log slow rules |
| [SecRuleRemoveById](#secruleremovebyid) | Core | yes | yes | yes | Remove rules by id |
| [SecRuleRemoveByMsg](#secruleremovebymsg) | Extended | yes | yes | yes | Remove rules by message |
| [SecRuleRemoveByTag](#secruleremovebytag) | Core | yes | yes | yes | Remove rules by tag |
| [SecRuleScript](#secrulescript) | Extended | yes | yes | yes | Lua rule |
| [SecRuleUpdateActionById](#secruleupdateactionbyid) | Core | yes | yes | yes | Edit actions of a rule |
| [SecRuleUpdateTargetById](#secruleupdatetargetbyid) | Core | yes | yes | yes | Edit variables of a rule by id |
| [SecRuleUpdateTargetByMsg](#secruleupdatetargetbymsg) | Extended | yes | yes | yes | Edit variables of rules by message |
| [SecRuleUpdateTargetByTag](#secruleupdatetargetbytag) | Core | yes | yes | yes | Edit variables of rules by tag |
| [SecRxPreFilter](#secrxprefilter) | Engine-specific | - | - | yes | Literal prefilter for @rx |
| [SecSensorId](#secsensorid) | Extended | yes | yes | yes | Sensor identifier in audit logs |
| [SecServerSignature](#secserversignature) | Extended | yes | yes | yes | Replace the server signature |
| [SecStatusEngine](#secstatusengine) | Deprecated | yes | yes | - | Report engine status upstream |
| [SecStreamInBodyInspection](#secstreaminbodyinspection) | Deprecated | yes | yes | - | Expose STREAM_INPUT_BODY |
| [SecStreamOutBodyInspection](#secstreamoutbodyinspection) | Deprecated | yes | yes | - | Expose STREAM_OUTPUT_BODY |
| [SecTmpDir](#sectmpdir) | Extended | yes | yes | yes | Directory for temporary files |
| [SecTmpSaveUploadedFiles](#sectmpsaveuploadedfiles) | Extended | yes | yes | - | Keep temporary upload files |
| [SecUnicodeCodePage](#secunicodecodepage) | Deprecated | yes | - | - | Code page for Unicode mapping |
| [SecUnicodeMapFile](#secunicodemapfile) | Extended | yes | yes | - | Unicode mapping file |
| [SecUploadDir](#secuploaddir) | Core | yes | yes | yes | Directory for kept uploads |
| [SecUploadFileLimit](#secuploadfilelimit) | Extended | yes | yes | yes | Maximum files per request |
| [SecUploadFileMode](#secuploadfilemode) | Core | yes | yes | yes | Permissions of kept uploads |
| [SecUploadKeepFiles](#secuploadkeepfiles) | Core | yes | yes | yes | Keep uploaded files |
| [SecWebAppId](#secwebappid) | Extended | yes | yes | yes | Application identifier for persistence and logs |
| [SecWriteStateLimit](#secwritestatelimit) | Deprecated | yes | - | - | Older name of SecConnWriteStateLimit |
| [SecXmlExternalEntity](#secxmlexternalentity) | Extended | yes | yes | - | Allow XML external entities |

## Rule-building directives

### Include

**Status:** Core

**Syntax.** `Include PATH`

**Semantics.** Defined in `01-lexical.md#include`: the named file, or every file matched
by a `*` glob, is parsed in place. Nested includes are permitted.

**Divergence notes.** Relative-path resolution differs (`01-lexical.md#include`).

**Tests.** `tests/engine/directives/include.yaml`,
`tests/engine/lexical/include-relative-file.yaml`

### SecAction

**Status:** Core

**Syntax.** `SecAction "ACTIONS"`

**Semantics.** An unconditional rule: it matches every transaction in its phase and runs
its action list (`02-grammar.md#secrule-structure`). `SecAction` is the idiomatic way to
initialise `TX` variables and to emit `ctl:` changes. It participates in `SecDefaultAction`
inheritance, chains, `skip`/`skipAfter` and rule exceptions exactly like a `SecRule`
whose operator always matches. It MUST carry an `id` unless it is a chain member.

**Divergence notes.** None known.

**Tests.** `tests/engine/directives/secaction.yaml`

### SecComponentSignature

**Status:** Core

**Syntax.** `SecComponentSignature "NAME/VERSION (COMMENT)"`

**Semantics.** Appends the string to the engine's component signature, which engines
include in audit log headers and debug logs so that the rule set version in use can be
identified. May appear more than once; each occurrence appends. No effect on rule
evaluation.

**Divergence notes.** None known.

**Tests.** `tests/engine/directives/seccomponentsignature.yaml`

### SecDefaultAction

**Status:** Core

**Syntax.** `SecDefaultAction "ACTIONS"`

**Semantics.** Defined in `03-processing-model.md#default-actions`. Constraints on the
action list are normative (ADR-0014).

**Default.** None in ModSecurity v2 and libmodsecurity v3: a rule that matches with no
disruptive action from any source passes. Coraza applies a built-in
`phase:2,log,auditlog,pass` (`internal/seclang/directives.go`). Observationally these
agree, since `pass` is the no-op disruptive action.

**Divergence notes.** See `03-processing-model.md#default-actions`.

**Tests.** `tests/engine/processing/default-action.yaml`,
`tests/engine/processing/default-action-no-phase.yaml`,
`tests/engine/processing/default-action-no-disruptive.yaml`

### SecMarker

**Status:** Core

**Syntax.** `SecMarker LABEL`

**Semantics.** Defines a phase-less label that `skipAfter:LABEL` jumps to
(`03-processing-model.md#flow-control`). A marker never evaluates anything, has no
actions and no id, and MAY be quoted. The same label MAY be defined more than once; the
first one after the skipping rule wins.

**Divergence notes.** None known.

**Tests.** `tests/engine/processing/skip-and-skipafter.yaml`

### SecRule

**Status:** Core

**Syntax.** `SecRule VARIABLES OPERATOR [ACTIONS]`

**Semantics.** The conditional rule, defined in `02-grammar.md#secrule-structure`,
`#variable-list`, `#operator` and `#action-list`, and evaluated as described in
`03-processing-model.md`. The variables are listed in `05-variables.md`, the operators in
`06-operators.md`, the transformations in `07-transformations.md` and the actions in
`08-actions.md`.

**Divergence notes.** None for the directive itself; see the referenced sections.

**Tests.** `tests/engine/grammar/variable-list.yaml` and every other engine-tier
profile in this repository.

### SecRuleRemoveById

**Status:** Core

**Syntax.** `SecRuleRemoveById ID|RANGE [ID|RANGE ...]`

**Semantics.** Removes every previously defined rule whose id is listed or falls in a
listed inclusive range (`03-processing-model.md#rule-exceptions`). Ids that match no rule
are ignored. A range with start greater than end MUST be a configuration error.

**Divergence notes.** ModSecurity v2 does not validate range order.

**Tests.** `tests/engine/directives/secruleremovebyid-range.yaml`,
`tests/engine/processing/rule-exceptions.yaml`,
`tests/engine/processing/rule-exceptions-bad-range.yaml`

### SecRuleRemoveByMsg

**Status:** Extended

**Syntax.** `SecRuleRemoveByMsg REGEX`

**Semantics.** Removes every previously defined rule whose `msg` matches the regular
expression (`03-processing-model.md#rule-exceptions`). Implemented by ModSecurity v2,
libmodsecurity v3 and Coraza; Extended rather than Core because OWASP CRS does not use
it and `msg` values are not stable identifiers.

### SecRuleRemoveByTag

**Status:** Core

**Syntax.** `SecRuleRemoveByTag REGEX`

**Semantics.** Removes every previously defined rule any of whose `tag` values matches
the regular expression, unanchored (`03-processing-model.md#rule-exceptions`).

**Divergence notes.** None known.

**Tests.** `tests/engine/processing/rule-exceptions.yaml`

### SecRuleUpdateActionById

**Status:** Core

**Syntax.** `SecRuleUpdateActionById ID|RANGE "ACTIONS"`

**Semantics.** Merges `ACTIONS` into each matching rule's action list; a disruptive
action replaces the existing one, cumulative actions are appended
(`03-processing-model.md#rule-exceptions`). `id` and `chain` MUST NOT appear in
`ACTIONS`.

**Divergence notes.** None known.

**Tests.** `tests/engine/processing/rule-exceptions-update-action.yaml`

### SecRuleUpdateTargetById

**Status:** Core

**Syntax.** `SecRuleUpdateTargetById ID|RANGE "TARGETS"`

**Semantics.** Appends `TARGETS` to the variable list of each matching rule; a target
beginning with `!` is an exclusion (`03-processing-model.md#rule-exceptions`). This is
the mechanism OWASP CRS documents for application-specific exclusions, used 57 times in
CRS v4 itself.

**Divergence notes.** None known.

**Tests.** `tests/engine/processing/rule-exceptions.yaml`

### SecRuleUpdateTargetByMsg

**Status:** Extended

**Syntax.** `SecRuleUpdateTargetByMsg REGEX "TARGETS"`

**Semantics.** As `SecRuleUpdateTargetById`, selecting rules by `msg`. Implemented by
ModSecurity v2 and libmodsecurity v3; Coraza 3.8.1 accepts and ignores it (ADR-0005).

### SecRuleUpdateTargetByTag

**Status:** Core

**Syntax.** `SecRuleUpdateTargetByTag REGEX "TARGETS"`

**Semantics.** As `SecRuleUpdateTargetById`, selecting every rule any of whose tags
matches `REGEX`.

**Divergence notes.** None known (Coraza added it in its ADR-0012).

**Tests.** `tests/engine/directives/secruleupdatetargetbytag.yaml`

## Engine and body directives

### SecRuleEngine

**Status:** Core

**Syntax.** `SecRuleEngine On|Off|DetectionOnly`

**Default.** `Off` in ModSecurity v2 (`apache2_config.c`, `is_enabled = 0`). `On` in
Coraza (`internal/corazawaf/waf.go`, `RuleEngine: types.RuleEngineOn`). libmodsecurity
v3 leaves the value unset (`PropertyNotSetRuleEngine`), in which state rules are
evaluated and logged but never interrupt, equivalent to `DetectionOnly`. Because the
three defaults differ, rulesets MUST set it explicitly and this specification does not
standardize the default.

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

**Divergence notes.** None known for the three values. The defaults differ as listed
above; every published ruleset sets the directive, so the default is left unspecified.

**Tests.** `tests/engine/directives/secruleengine-on.yaml`,
`tests/engine/directives/secruleengine-detectiononly.yaml`,
`tests/engine/directives/secruleengine-off.yaml`
