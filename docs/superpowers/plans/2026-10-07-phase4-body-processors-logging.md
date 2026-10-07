# SecLang Spec Phase 4 (Body Processors, Logging, Deferred Minors) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the specification's first draft with the two remaining files, body processors (`09`) and logging (`10`), each with tests and an ADR for the divergence it uncovers; then clear every minor deferred by the three previous reviews and mark the draft as version 0.1.

**Architecture:** `09-body-processors.md` specifies processor selection and the four processors (`URLENCODED`, `MULTIPART`, `XML`, `JSON`) as Core features with engine tests; JSON argument naming is left unspecified by ADR-0020. `10-logging.md` specifies the minimum portable logging contract: an error-log line per match carrying `[id "…"]` and `[msg "…"]`, audit-log relevance and parts, the Native format as Core and JSON as Extended with an unspecified shape (ADR-0021). The deferred minors are tooling fixes with tests and wording corrections.

**Tech Stack:** Markdown, YAML, JSON; Python via `uv run`.

**Spec:** `docs/superpowers/specs/2026-10-06-seclang-spec-design.md` section 4.1 (files 09, 10) and 4.4 ("Logging tests assert only on rule IDs and `msg` presence"); `spec/00-conventions.md`; ledgers' deferred-minor lines reproduced in Task 3.

## Global Constraints

- Feature headings `### Name` with `**Status:**` first; every Core feature tested; `uv run python tools/validate.py` → `0 error(s)` and `uv run python -m unittest discover -s tools -t .` → `OK` at the end of every task (commits gate on **both**).
- Engine facts cite source. Surveyed 2026-10-07: v2 `apache2/msc_reqbody.c`, `msc_parsers.c`, `msc_json.c`, `msc_xml.c`, `msc_multipart.c`, `msc_logging.c`, `mod_security2.c`, `re.c`; v3 `src/transaction.cc`, `src/request_body_processor/{json,xml,multipart}.cc`, `src/rule_message.cc`, `src/audit_log/`; Coraza `internal/corazawaf/transaction.go`, `internal/bodyprocessors/*.go`, `internal/url/url.go`, `internal/corazarules/rule_match.go`, `internal/auditlog/`.
- Logging tests use `log_contains` with the rule's `msg` text only; never the engine prefix, file, line or wording.
- Divergences the spec follows the majority on get a note plus a `compat/known-gaps.md` row; a decision against a majority or a decision to leave something unspecified where users might expect a rule gets an ADR.

## Review Focus

1. A body with `Content-Type: application/x-www-form-urlencoded; charset=utf-8` (parameter present). Expected: still selects `URLENCODED` (all three compare by prefix: v3 `transaction.cc:585` `compare(0, len)`, Coraza `transaction.go:412` `HasPrefix`, v2 `strncasecmp`); test in Task 1 `selection.yaml`.
2. A urlencoded body `a=1&b` (key without `=`). Expected: `ARGS_POST:b` exists with an empty value in all three (v2 `msc_parsers.c` `value_len = 0`); test in Task 1 `urlencoded.yaml`.
3. A multipart body whose part has `Content-Disposition: form-data; name="f"` **without** `filename`. Expected: it is an `ARGS_POST` member, not a `FILES` member; test in Task 1 `multipart-fields.yaml`.
4. An XML body declaring an external entity. Expected: not resolved by default in any engine (v2 `msc_xml.c:163` `xml_external_entity == 0`; v3 `xml.cc:176` `m_secXMLExternalEntity`; Coraza `encoding/xml` never loads external entities); test in Task 1 `xml-no-xxe.yaml` asserts the entity text is absent from `XML:/*`.
5. A matched rule whose `msg` contains a double quote. Expected: `log_contains` on a substring without the quote still works, so the test avoids quotes; Task 2 documents that `msg` quoting in logs is engine-specific.

---

### Task 1: `spec/09-body-processors.md`, tests, ADR-0020

**Files:**
- Create: `spec/09-body-processors.md`
- Create: `tests/engine/body/selection.yaml`, `urlencoded.yaml`, `multipart-fields.yaml`, `multipart-two-files.yaml`, `xml-no-xxe.yaml`, `json-args.yaml`, `no-processor.yaml`
- Create: `adr/0020-json-argument-names.md`; modify `adr/README.md`
- Modify: `compat/known-gaps.md`

**Interfaces:**
- Anchors (all Core unless stated): `09-body-processors.md#processor-selection`, `#urlencoded`, `#multipart`, `#xml`, `#json`, `#raw` (Engine-specific, Coraza), `#response-body-processors` (Engine-specific, Coraza). These are concept headings (hyphenated or not) with no matrix category; `check_matrix_status` ignores files not in `MATRIX_SPEC_FILES`, so no tooling change.

**Facts to state:**
- Selection (`#processor-selection`): when `SecRequestBodyAccess` is `On`, the processor is chosen from the request `Content-Type` by prefix match: `application/x-www-form-urlencoded` → `URLENCODED`, `multipart/form-data` → `MULTIPART`; any other type → **no processor** (body buffered, `REQUEST_BODY` empty unless `ctl:forceRequestBodyVariable=On`, `ARGS_POST` empty). `XML` and `JSON` are selected only by `ctl:requestBodyProcessor` in phase 1, which the recommended configurations do for `text/xml`/`application/xml` and `application/json` (rules 200000, 200001). `REQBODY_PROCESSOR` reports the choice. (v3 `transaction.cc:577-586`, Coraza `transaction.go:412-414`, v2 `mod_security2.c`/`msc_reqbody.c`.)
- `URLENCODED`: split on `SecArgumentSeparator`, each pair on the first `=`; a pair without `=` is a name with empty value; names and values are URL-decoded (`%XX`, `+` → space) non-strictly: an invalid `%` sequence is kept literally and, in ModSecurity v2 and libmodsecurity v3, sets `URLENCODED_ERROR` to 1 (`msc_parsers.c` `urldecode_nonstrict_inplace_ex`, `transaction.cc:271`); Coraza never sets `URLENCODED_ERROR` (`UrlencodedError()` has no writer), which is why that variable is Extended. Also populates `REQUEST_BODY` and `REQUEST_BODY_LENGTH`.
- `MULTIPART`: RFC 7578 parsing with the boundary from `Content-Type`; parts with `filename` become `FILES`/`FILES_NAMES`/`FILES_SIZES`/`FILES_COMBINED_SIZE` and their content is not exposed as a variable; parts without `filename` become `ARGS_POST`; `MULTIPART_PART_HEADERS` per part; anomalies set `MULTIPART_STRICT_ERROR` (per-engine set, `05-variables.md#multipart_strict_error`); `SecUploadFileLimit` caps file parts (`MULTIPART_FILE_LIMIT_EXCEEDED` Extended); `SecRequestBodyNoFilesLimit` applies to non-file bytes (`04`); `REQUEST_BODY` is empty.
- `XML`: parses the body as XML; `XML:/*` and `XML://@*` (`05`); external entities MUST NOT be resolved unless `SecXmlExternalEntity On` (Extended); a malformed document sets `REQBODY_ERROR`. v2/v3 libxml2; Coraza `encoding/xml` with `Strict = false` and HTML entities (`xml.go:37-39`), so Coraza tolerates some malformed XML that libxml2 rejects: **divergence note**, no test on malformed XML.
- `JSON`: parses the body; leaves become `ARGS_POST` members (and so `ARGS`); depth limited by `SecRequestBodyJsonDepthLimit`; malformed → `REQBODY_ERROR`. **Argument names are not specified** (ADR-0020): v2 uses the bare key path (`a.b`, arrays under `array`; `msc_json.c:28-41, 176-180`), v3 builds `container.array_N.key` paths (`json.cc:100-150`), Coraza prefixes `json.` and numbers array elements (`bodyprocessors/json.go` `readItems`). Portable rules target `ARGS`/`ARGS_NAMES` as a whole, as CRS does; the test asserts count and value only.
- `RAW` and response processors: Coraza-only (`bodyprocessors/raw.go`, `ProcessResponse` in every processor, `ctl:responseBodyProcessor`, `RESPONSE_ARGS`, `RESPONSE_XML`, `RES_BODY_*`); Engine-specific.

**Tests** (ids 8000–8099, all with `SecRuleEngine On`, `SecRequestBodyAccess On`):
- `selection.yaml` (`#processor-selection`): three stages: urlencoded with charset parameter → `REQBODY_PROCESSOR @streq URLENCODED` fires; `multipart/form-data; boundary=X` → `MULTIPART`; `text/plain` → rule `&REQBODY_PROCESSOR "@eq 0"`? Engines may set the variable to empty string rather than absent; assert instead `REQBODY_PROCESSOR "!@rx ^(URLENCODED|MULTIPART|XML|JSON)$"` fires.
- `urlencoded.yaml` (`#urlencoded`): body `a=1&b&c=x+y%20z&d=%zz` → `ARGS_POST:b @streq ""`? Empty-string operator param is awkward; use `&ARGS_POST:b "@eq 1"` and `ARGS_POST:b "!@rx ."`; `ARGS_POST:c "@streq x y z"`; `ARGS_POST:d "@streq %zz"`; `&ARGS_POST "@eq 4"`; `REQUEST_BODY_LENGTH "@eq 21"` (count the bytes when writing). No `URLENCODED_ERROR` assertion (Extended).
- `multipart-fields.yaml` (`#multipart`): one text field `name="t"` value `hello`, one file `name="f"; filename="a.txt"` → `ARGS_POST:t @streq hello`, `&FILES "@eq 1"`, `FILES:f @streq a.txt`, `&ARGS_POST "@eq 1"` (file is not an arg), `REQUEST_BODY "!@rx ."` (empty).
- `multipart-two-files.yaml` (`#multipart`): two file parts, 3 and 4 bytes → `&FILES "@eq 2"`, `FILES_COMBINED_SIZE "@eq 7"`, `FILES_NAMES` contains both names (`&FILES_NAMES "@eq 2"`).
- `xml-no-xxe.yaml` (`#xml`): `<!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><a>&xxe;</a>` with ctl XML → `XML:/* "!@contains root"`? The hostname is unknown; assert `XML:/* "!@rx ."` is wrong if libxml2 leaves `&xxe;` unexpanded as empty text vs. Coraza leaving literal `&xxe;`. Safer: `<a>x&xxe;y</a>` and assert `XML:/* "@rx ^x.{0,6}y$"`? Still fragile. Decision: assert only `REQBODY_ERROR "!@eq 1"` is **not** asserted either (libxml2 may error). Keep the profile as a **load + no crash** check: a phase-2 `SecRule REQUEST_METHOD "@streq POST" "id:8040,pass"` fires and `XML://@*` of a sibling attribute `<a k="v">…` equals `v`. Document in the section that XXE must not be resolved and that the test cannot observe resolution portably.
- `json-args.yaml` (`#json`): body `{"a":1,"b":{"c":"x"},"d":[1,2]}` with ctl JSON → `&ARGS_POST "@eq 4"`, `ARGS_POST "@streq x"` (some member has value x), `ARGS_NAMES "@rx (?i)(^|\.)c$"` (some name ends in `c`, works for `b.c`, `json.b.c`). Divergence note explains why names are not asserted exactly.
- `no-processor.yaml` (`#processor-selection`): `text/plain` body `a=1` → `&ARGS_POST "@eq 0"`, `REQUEST_BODY "!@rx ."` without ctl; second stage with `ctl:forceRequestBodyVariable=On` → `REQUEST_BODY "@streq a=1"`.

**ADR-0020 (Clarification): JSON argument names are unspecified.** Context as above with the three naming schemes; decision: the set of leaf values and their count are normative, names are not; rule authors target `ARGS` wholesale or use `ARGS_NAMES` regexes anchored at the end; a future Divergence ADR may pick a scheme once an engine is willing to change. Consequences; tests: `json-args.yaml`.

- [ ] Steps: tests → validator RED → write `09` → ADR-0020 + index row → known-gaps row for Coraza `URLENCODED_ERROR`? (Extended → no row) → GREEN → commit `spec: body processors with tests; ADR-0020 JSON argument names`.

---

### Task 2: `spec/10-logging.md`, tests, ADR-0021

**Files:**
- Create: `spec/10-logging.md`
- Create: `tests/engine/logging/error-log-fields.yaml`, `audit-relevance-load.yaml`
- Create: `adr/0021-logging-contract.md`; modify `adr/README.md`

**Interfaces:** anchors `10-logging.md#error-log` (Core), `#audit-log-relevance` (Core), `#audit-log-parts` (Core), `#native-format` (Core), `#json-format` (Extended), `#debug-log` (Extended).

**Facts to state:**
- Error log: one line per matched rule that is not `nolog`, written to the host error log. Portable content: the fields `[id "N"]` and `[msg "TEXT"]` (v2 `re.c:1725-1729` `[file] [line] [id]`, `msc_logging.c`; v3 `rule_message.cc:31-33`; Coraza `corazarules/rule_match.go:251-308`). The line prefix (`ModSecurity: Warning.`, `ModSecurity: Access denied with code N`, `Coraza: Warning.`, `Coraza: Access denied (phase N).`) and the remaining fields (`[file]`, `[line]`, `[data]`, `[severity]`, `[ver]`, `[tag]`, `[hostname]`, `[uri]`, `[unique_id]`) are engine-specific in presence and wording. Tests MAY assert on the `msg` text; MUST NOT assert on anything else.
- Audit log relevance: an entry is written when `SecAuditEngine On`; or `RelevantOnly` and either a matched rule carried `auditlog` (and not `noauditlog`) or the response status matches `SecAuditLogRelevantStatus`. `ctl:auditEngine` per transaction. `nolog` implies `noauditlog` unless `auditlog` is explicit (`08`).
- Audit log parts: letters per `04#secauditlogparts`; the content of each part in prose (A: header with timestamp, unique id, client/server addresses; B: request headers; C: request body; E: intermediary response body; F: response headers; H: trailer with messages, stopwatch, producer, engine mode; I: body without files; J: file information; K: matched rules; Z: terminator). Engines differ in which they fill (Coraza: no D, E, G). Content wording is engine-specific; this specification requires only that parts A, B, F, H and Z exist when requested and that H (or K) names each matched rule's id.
- Native format: `--BOUNDARY-X--` markers per part, boundary unique per entry (v2 `msc_logging.c`, v3 `toOldAuditLogFormat`/`writer.cc generateBoundary`, Coraza `auditlog/formats.go:54`). Core as the one format all three write identically in structure.
- JSON format: v2 (`AUDITLOGFORMAT_JSON`), v3 (`JSONAuditLogFormat`), Coraza (`json`, plus `jsonlegacy` approximating v2's shape, `ocsf`): three different object shapes → Extended, shape unspecified (ADR-0021).
- Debug log: `SecDebugLog`/`SecDebugLogLevel`; wording never specified; Extended as a feature because levels 1–3 mirror the error log in ModSecurity but Coraza's structured logger differs (its ADR-0009).

**Tests:**
- `error-log-fields.yaml` (`#error-log`): rule with `msg:'seclang spec logging probe'` fires on `?a=1`; `output.log_contains: seclang spec logging probe`; a `nolog` rule with `msg:'must not appear'` → `no_log_contains: must not appear`.
- `audit-relevance-load.yaml` (`#audit-log-relevance`, per-test anchors for `#audit-log-parts`, `#native-format`): `SecAuditEngine RelevantOnly`, `SecAuditLog /dev/null`, `SecAuditLogFormat Native`, `SecAuditLogParts ABFHZ`, rule with `auditlog`; asserts the rule fires (observability of the entry itself is outside the schema; the section says so).

**ADR-0021 (Clarification): the portable logging contract is rule ids and messages.** Context: three error-log prefixes, three JSON audit shapes, part contents differ; design 4.4 already excludes layout assertions. Decision: normative = presence of `[id]` and `[msg]` per match in the error log; Native audit format structure; everything else engine-specific. Consequence: adapters implement `log_contains` over the error log (or the engine's matched-rule messages) only.

- [ ] Steps: tests → RED → write `10` → ADR-0021 + index → GREEN → commit `spec: logging contract with tests; ADR-0021`.

---

### Task 3: Deferred minors from three reviews

**Tooling (each with a unit test first):**
- `tools/validate.py` `check_adrs`: compare each index row's number, Category and Status with the file's header; report mismatches. Verify `## Tests` paths exist for **every** ADR that lists any (keep "at least one" Divergence-only).
- `check_matrix`: catch `FileNotFoundError` for a missing `compat/matrix.json`; `matrix.render` reports a row without `name` by index.
- `check_tests`: a missing schema file is a one-line error, not a traceback; `files` keys starting with `/` rejected.
- `HEADING_RE`: restrict features to `###` headings (00-conventions says `###`); confirm no existing `##`/`####` heading carries a status (grep first).
- `check_matrix_status`: report Deprecated rows that are `-` for an engine as a *warning-grade* line? The validator has no warning level; instead add them to the README of `compat/` as a generated section? **Decision:** skip, record in ledger as declined (ADR-0005 already lists them).
- `tools/test_validate.py`: move the mid-file `__main__` guard to the end; imports to the top.
- Prefix exemption: compare against the actual prefixed rows' anchors instead of the literal prefix (`frag.startswith(prefix) and frag in by_anchor_of_prefixed`), with a test that a heading `### ctlfoo` without a ctl row is reported.

**Spec/ADR wording:**
- `00-conventions.md`: feature-kind sentence adds "and any other section that carries a status line"; "the first non-blank line after its heading"; document version line "Draft 0.1, 2026-10-07".
- `ADR-0002`: "lowercase at both `Register` and `Get`".
- `README.md`: Python floor (3.10+; CI pins 3.12); mention `compat/known-gaps.md`, `tools/import_sts.py`, draft version.
- `.github/workflows/validate.yml`: drop `-v`.
- `ADR-0014` Context: note v2 keeps one current default action set (points to ADR-0017).
- `07#escapeseqdecode`: invalid sequence drops the backslash and keeps the byte; only an incomplete `\x` is kept verbatim (v2 `msc_util.c:1893`).
- `06#pm`: move the capture sentence into Divergence notes: v2/v3 capture the phrase, Coraza does not.
- `06#unconditionalmatch`: drop the "with no values still matches once" sentence unless verified in all three in this task (check v3 `unconditional_match.cc` / rule evaluation with empty variable list; v2 `re.c`; Coraza `rule.go`): record the finding either way.
- `08#redirect`: v3 accepts any 301–307; note.
- `ADR-0011`: remove `@rsub` from the legacy list or move `rsub` to Deprecated in `06` and the matrix; **decision:** `rsub` depends on `STREAM_*` which are Deprecated, so make `rsub` Deprecated too (update `06`, matrix status, importer has no rsub file).
- `05#request_uri`: Coraza re-serialises via `url.URL.String()`; note.

- [ ] Steps: tooling tests RED → GREEN; wording edits; validator GREEN; commit `chore: deferred review minors (tooling checks, wording, rsub Deprecated)`.

---

### Task 4: Draft 0.1 wrap-up

- `README.md`: state that files 00–10 exist, the draft version, the ADR count, how engines adopt the tests (pointer to `tests/README.md`), and the known-gaps table.
- `spec/00-conventions.md`: add a "Document status" paragraph: Draft 0.1, all ADRs `proposed`, what acceptance requires.
- `compat/known-gaps.md`: intro sentence names the three engine versions surveyed.
- Validator and suite green; commit `docs: draft 0.1`.

---

## Self-review notes

- **Spec coverage:** design 4.1 files 09 and 10 → Tasks 1–2; 4.4 logging assertion rule → Task 2 and ADR-0021; deferred minors from ledgers → Task 3; versioning (00-conventions) → Task 4.
- **Review Focus mapping:** 1 → `selection.yaml`; 2 → `urlencoded.yaml`; 3 → `multipart-fields.yaml`; 4 → `xml-no-xxe.yaml` (documented limitation); 5 → Task 2 text.
- **Open calls for the reviewer:** JSON argument names left unspecified rather than picking a scheme; `rsub` moved to Deprecated; XXE test reduced to a load check because resolution is not portably observable.
