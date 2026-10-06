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

### SecArgumentSeparator

**Status:** Core

**Syntax.** `SecArgumentSeparator CHAR`

**Default.** `&` (all engines).

**Scope.** Main configuration; applies to every transaction.

**Semantics.** The single character that separates `name=value` pairs when parsing the
query string and `application/x-www-form-urlencoded` request bodies into `ARGS_GET` and
`ARGS_POST`. Changing it to `;` supports applications that use the W3C-recommended
alternative separator.

**Divergence notes.** ModSecurity v2 (`apache2/msc_parsers.c`) and libmodsecurity v3
(`src/transaction.cc`, `m_secArgumentSeparator`) implement it for both the query string
and the body. Coraza 3.8.1 parses the directive and ignores it
(`directivesmap.gen.go` maps it to `directiveUnsupported`), so the test fails there: a
Core gap (ADR-0005).

**Tests.** `tests/engine/directives/secargumentseparator.yaml`

### SecArgumentsLimit

**Status:** Core

**Syntax.** `SecArgumentsLimit N`

**Default.** 1000 in ModSecurity v2 (`ARGUMENTS_LIMIT`) and Coraza (`waf.go`);
libmodsecurity v3 applies no limit until the directive is set. Unspecified.

**Semantics.** At most `N` arguments are added to `ARGS_GET` and `ARGS_POST` combined;
arguments parsed after the limit is reached are discarded and do not appear in any
collection or count. Engines SHOULD log the discard at debug level. Coraza additionally
exposes `ARGUMENTS_LIMIT_REACHED` (Engine-specific, `05-variables.md`).

**Divergence notes.** None for the discard behaviour (v2 `msc_parsers.c` "Skipping
request argument, over limit"; v3 `transaction.cc` same message; Coraza `waf.go`).

**Tests.** `tests/engine/directives/secargumentslimit.yaml`

### SecRequestBodyAccess

**Status:** Core

**Syntax.** `SecRequestBodyAccess On|Off`

**Default.** `Off` in ModSecurity v2 and Coraza; unset in libmodsecurity v3, which
behaves as `Off`. Normative default: `Off`.

**Semantics.** When `On`, the engine buffers the request body up to
`SecRequestBodyLimit`, runs the body processor selected by `Content-Type` or
`ctl:requestBodyProcessor`, and populates `ARGS_POST`, `REQUEST_BODY`, `FILES*`, `XML`
and `JSON` before phase 2. When `Off`, the body is not read and those variables are
empty. `ctl:requestBodyAccess` overrides the value for one transaction when set in
phase 1.

**Divergence notes.** None known.

**Tests.** `tests/engine/directives/secrequestbodyaccess.yaml`,
`tests/engine/directives/secrequestbodyaccess-off.yaml`

### SecRequestBodyLimit

**Status:** Core

**Syntax.** `SecRequestBodyLimit BYTES`

**Default.** 134217728 (128 MiB) in ModSecurity v2 (`REQUEST_BODY_DEFAULT_LIMIT`) and
Coraza (`waf.go`); libmodsecurity v3 applies no limit until set. Unspecified; both
recommended configurations set 13107200.

**Semantics.** The maximum request body size the engine will buffer, including file
uploads. What happens above the limit is governed by `SecRequestBodyLimitAction`. The
value MUST be a positive integer. The value `0` is **not specified**: libmodsecurity v3
treats it as "no limit" (`transaction.cc` tests `m_value > 0`), Coraza rejects it at
load time (`waf.go` `Validate`, "request body limit should be bigger than 0") and
ModSecurity v2 treats it as a zero-byte limit. Portable configurations never use `0`.

**Divergence notes.** The HTTP status used by `Reject` is 413 in ModSecurity v2
(`msc_reqbody.c`, `HTTP_REQUEST_ENTITY_TOO_LARGE`) and Coraza (`transaction.go`,
`setAndReturnBodyLimitInterruption(tx, 413)`) but 403 in libmodsecurity v3
(`transaction.cc`, `m_it.status = 403`). The tests therefore assert only that the
transaction is denied. Coraza also caps the value at 1 GiB.

**Tests.** `tests/engine/directives/secrequestbodylimit-reject.yaml`,
`tests/engine/directives/body-limit-directives-load.yaml`

### SecRequestBodyLimitAction

**Status:** Core

**Syntax.** `SecRequestBodyLimitAction Reject|ProcessPartial`

**Default.** `Reject` in ModSecurity v2 (`REQUEST_BODY_LIMIT_ACTION_REJECT`) and Coraza;
unset in libmodsecurity v3. Unspecified.

**Semantics.** `Reject`: when the body exceeds `SecRequestBodyLimit` the transaction is
interrupted with a `deny` before phase 2 rules run; the interruption carries no rule id
(adapters report `rule_id: 0`). `ProcessPartial`: the first `SecRequestBodyLimit` bytes
are buffered and processed, the rest is discarded, `INBOUND_DATA_ERROR` is set to `1`,
and phase 2 rules run normally. In `DetectionOnly`, `Reject` MUST NOT interrupt.

**Divergence notes.** Status code for `Reject` differs (see `#secrequestbodylimit`).

**Tests.** `tests/engine/directives/secrequestbodylimit-processpartial.yaml`,
`tests/engine/directives/secrequestbodylimit-reject.yaml`

### SecRequestBodyNoFilesLimit

**Status:** Core

**Syntax.** `SecRequestBodyNoFilesLimit BYTES`

**Default.** 1048576 (1 MiB) in ModSecurity v2 (`REQUEST_BODY_NO_FILES_DEFAULT_LIMIT`)
and Coraza; unset in libmodsecurity v3. Unspecified.

**Semantics.** A second size limit that excludes the bytes of uploaded files in
`multipart/form-data` bodies, so that large uploads can be allowed while keeping the
inspected part of the body small. Exceeding it MUST be treated as exceeding
`SecRequestBodyLimit` under `SecRequestBodyLimitAction`.

**Divergence notes.** The enforcement path differs: ModSecurity v2 rejects
(`msc_reqbody.c`); libmodsecurity v3 sets `REQBODY_ERROR`, `REQBODY_ERROR_MSG` and
`INBOUND_DATA_ERROR` (`transaction.cc`); Coraza 3.8.1 reads the directive but
implements no logic (`waf.go`, "TODO ... no logic based on it is implemented", issue
896). Until a Divergence ADR fixes the observable behaviour, the test only checks that
the directive loads. A Core gap for Coraza (ADR-0005).

**Tests.** `tests/engine/directives/body-limit-directives-load.yaml`

### SecRequestBodyInMemoryLimit

**Status:** Core

**Syntax.** `SecRequestBodyInMemoryLimit BYTES`

**Default.** 131072 in ModSecurity v2 (`REQUEST_BODY_DEFAULT_INMEMORY_LIMIT`); equal to
`SecRequestBodyLimit` in Coraza (`waf.go`); unset in libmodsecurity v3. Unspecified.

**Semantics.** The number of request body bytes held in memory before the engine spools
the remainder to a temporary file. It has no effect on rule evaluation; it exists so
that deployments can bound memory use (see Coraza's `RATIONALE.md`). Engines without
filesystem access MAY treat it as equal to `SecRequestBodyLimit`.

**Divergence notes.** Defaults differ as listed; no observable rule-level divergence.

**Tests.** `tests/engine/directives/body-limit-directives-load.yaml`

### SecRequestBodyJsonDepthLimit

**Status:** Core

**Syntax.** `SecRequestBodyJsonDepthLimit N`

**Default.** 10000 in ModSecurity v2 (`REQUEST_BODY_JSON_DEPTH_DEFAULT_LIMIT`) and
libmodsecurity v3 (`json.cc`, `json_depth_limit_default`); 1024 in Coraza (`waf.go`,
`DefaultRequestBodyJsonDepthLimit`). Unspecified.

**Semantics.** The maximum nesting depth of a JSON request body processed by the `JSON`
body processor. A body nested deeper MUST be treated as a body processing error:
`REQBODY_ERROR` is set to `1` and `REQBODY_ERROR_MSG` describes the failure; rules then
decide what to do, as OWASP CRS rule 200002 does.

**Divergence notes.** Defaults differ as listed.

**Tests.** `tests/engine/directives/secrequestbodyjsondepthlimit.yaml`

### SecResponseBodyAccess

**Status:** Core

**Syntax.** `SecResponseBodyAccess On|Off`

**Default.** `Off` in ModSecurity v2 and Coraza; unset in libmodsecurity v3, which
behaves as `Off`. Normative default: `Off`.

**Semantics.** When `On`, and the response `Content-Type` is listed by
`SecResponseBodyMimeType`, the engine buffers the response body up to
`SecResponseBodyLimit` and makes it available as `RESPONSE_BODY` in phase 4. When `Off`,
phase 4 runs with an empty `RESPONSE_BODY`.

**Divergence notes.** None known.

**Tests.** `tests/engine/directives/secresponsebodyaccess.yaml`,
`tests/engine/directives/secresponsebodyaccess-off.yaml`

### SecResponseBodyLimit

**Status:** Core

**Syntax.** `SecResponseBodyLimit BYTES`

**Default.** 524288 (512 KiB) in ModSecurity v2 (`RESPONSE_BODY_DEFAULT_LIMIT`) and
Coraza (`waf.go`); libmodsecurity v3 applies no limit until set. Unspecified.

**Semantics.** The maximum response body size the engine will buffer. Behaviour above
the limit is governed by `SecResponseBodyLimitAction`.

**Divergence notes.** None beyond the defaults.

**Tests.** `tests/engine/directives/secresponsebodylimit-processpartial.yaml`,
`tests/engine/directives/body-limit-directives-load.yaml`

### SecResponseBodyLimitAction

**Status:** Core

**Syntax.** `SecResponseBodyLimitAction Reject|ProcessPartial`

**Default.** `Reject` in ModSecurity v2 (`RESPONSE_BODY_LIMIT_ACTION_REJECT`);
`ProcessPartial` in Coraza (`waf.go`, `BodyLimitActionProcessPartial`); unset in
libmodsecurity v3. Unspecified, and this is the one body-limit default where engines
disagree on *behaviour* rather than on a number: configurations MUST set it.

**Semantics.** `Reject`: a response larger than the limit is replaced by a `deny`
interruption (status 403 in every engine, since the limit is reached in phase 4).
`ProcessPartial`: the first `SecResponseBodyLimit` bytes are inspected,
`OUTBOUND_DATA_ERROR` is set to `1`, and the full response is delivered.

**Divergence notes.** Defaults differ as listed.

**Tests.** `tests/engine/directives/secresponsebodylimit-reject.yaml`,
`tests/engine/directives/secresponsebodylimit-processpartial.yaml`

### SecResponseBodyMimeType

**Status:** Core

**Syntax.** `SecResponseBodyMimeType TYPE [TYPE ...]`

**Default.** ModSecurity v2 inspects `text/plain` and `text/html`
(`apache2_config.c`); libmodsecurity v3 inspects every type until the directive is set
(`transaction.cc`, the type check runs only when `m_set`); Coraza inspects none until set
(`transaction.go`, `IsResponseBodyProcessable`). Unspecified; both recommended
configurations set the list.

**Semantics.** Adds the given media types to the set whose response bodies are buffered
and inspected (`#secresponsebodyaccess`). Multiple occurrences accumulate. Types are
compared case-insensitively against the response `Content-Type` with any parameters
(`; charset=…`) removed. The tests use bare `Content-Type` values so that parameter
stripping is not what they measure.

**Divergence notes.** Defaults differ as listed.

**Tests.** `tests/engine/directives/secresponsebodymimetype.yaml`

### SecResponseBodyMimeTypesClear

**Status:** Core

**Syntax.** `SecResponseBodyMimeTypesClear`

**Semantics.** Empties the set of inspected response media types, including any engine
default, so that a following `SecResponseBodyMimeType` defines it from scratch.

**Divergence notes.** None known.

**Tests.** `tests/engine/directives/secresponsebodymimetypesclear.yaml`

### SecResponseBodyJsonDepthLimit

**Status:** Engine-specific

**Syntax.** `SecResponseBodyJsonDepthLimit N`

**Semantics.** Coraza only (its ADR-0059): the response-side counterpart of
`SecRequestBodyJsonDepthLimit` for the response JSON body processor, default 1024.
Neither ModSecurity branch parses response bodies as JSON.

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
