# libmodsecurity v3 Reference Adapter — Design

Status: approved in conversation, 2026-10-07.

## 1. Brief

**You said.** Create the libmodsecurity v3 adapter; CI builds v3.0.16 from source.

**Agreed.** A Python module under `adapters/libmodsecurity` that runs the conformance data
in `tests/` against libmodsecurity v3.0.16 through its C API (`ctypes`, no compiled
glue), as `unittest`, in CI, with `compat/known-gaps.md` acting as the expected-failure
list exactly as the Coraza adapter does (ADR-0023).

**Assumptions.**

- Python with `uv` is the repository's tooling; the adapter adds no dependency beyond
  the existing `pyyaml` dev group entry (ctypes is stdlib).
- The library under test is whatever `MODSECURITY_LIB` points at (a `libmodsecurity.so`
  or `.dylib`), built with libxml2, yajl and PCRE2 so that XML, JSON and the regex
  operators are available. CI builds it; locally a developer builds it once.
- libmodsecurity exposes no "matched rules including nolog" API, so matched rules are
  read from the engine's own debug log, which the adapter enables per rule set. The
  debug log is an engine feature, not a test contract: the adapter depends on four
  level-4 line formats from v3.0.16 (`(Rule: N) …`, `Rule returned 0|1.`,
  `Executing unconditional rule…`, `Running (disruptive)     action: name.`).
- Known-gaps rows for "libmodsecurity v3" become verified; rows for ModSecurity v2 stay
  predictions.

## 2. Shape

```
adapters/libmodsecurity/
  README.md            how to build the library, how to run, how results map to known-gaps
  mscapi.py            ctypes binding: load MODSECURITY_LIB, signatures, Intervention struct,
                       log callback; thin classes ModSecurity / RulesSet / Transaction
  data.py              load tests/engine YAML and tests/unit JSON (dataclasses mirroring the
                       schemas), repo root, latin1(), byte_string()
  engine_tier.py       build a rules set for a profile (files + rules file under a temp dir,
                       debug log appended), run one stage -> Observed, parse_debug_log(),
                       check_stage()
  unit_tier.py         unit rule set text, run_unit() -> UnitResult, check_unit()
  gaps.py              parse compat/known-gaps.md rows for an engine name
  test_conformance.py  TestEngine, TestUnit: one subTest per file, gated by known-gaps
  test_adapter.py      the adapter's own tests (parsers, loaders, one real-engine smoke test)
```

Run: `MODSECURITY_LIB=/path/to/libmodsecurity.so uv run python -m unittest discover -s adapters/libmodsecurity`.
Without `MODSECURITY_LIB` the conformance tests and the smoke test are skipped with a
message; the pure parsers still run.

## 3. Library binding

`mscapi.load()` opens `MODSECURITY_LIB` with `ctypes.CDLL(path, mode=RTLD_GLOBAL)` and
declares the functions used: `msc_init`, `msc_set_log_cb`, `msc_who_am_i`,
`msc_create_rules_set`, `msc_rules_add_file`, `msc_rules_cleanup`, `msc_new_transaction`,
`msc_process_connection`, `msc_process_uri`, `msc_add_request_header`,
`msc_process_request_headers`, `msc_append_request_body`, `msc_process_request_body`,
`msc_add_response_header`, `msc_process_response_headers`, `msc_append_response_body`,
`msc_process_response_body`, `msc_process_logging`, `msc_intervention`,
`msc_intervention_cleanup`, `msc_transaction_cleanup`. `ModSecurityIntervention` is
`{int status; int pause; char *url; char *log; int disruptive}`.

One `ModSecurity` instance per process; its log callback appends every line to a list
the current transaction owns. A missing or unloadable library is an error at import of
the conformance module, reported once. A library built without libxml2 or yajl makes
the XML and JSON profiles fail; the README says which configure flags CI uses.

## 4. Engine tier

Per profile: write `files:` entries under a temporary directory; write
`rules.conf` = profile `rules` + `SecDebugLog <dir>/debug.log` + `SecDebugLogLevel 4`
(appended last so they win over anything the profile sets); load it with
`msc_rules_add_file` so relative `Include` paths resolve against that directory.
`expect_error` asserts that the load returns an error. `requires:` is compared with the
Extended anchors v3 implements, initially `{05-variables.md#persistent-collections}`
(in-memory backend); anything else skips the profile.

Each stage mirrors the Coraza driver: `msc_process_connection(remote_addr or 127.0.0.1,
12345, 127.0.0.1, 80)`, `msc_process_uri(uri or /, method or GET, version with any
`HTTP/` prefix removed, default 1.1)`, request headers (plus `Host: localhost` when
absent), `msc_process_request_headers`, `msc_append_request_body(data as UTF-8 bytes)`,
`msc_process_request_body`; when the stage has a `response`: response headers,
`msc_process_response_headers(status or 200, "HTTP 1.1")`, `msc_append_response_body`,
`msc_process_response_body`; always `msc_process_logging`. After each phase call
`msc_intervention` is consulted; once it reports `disruptive`, later phases are not
driven (logging still is), matching the Coraza adapter.

Observation sources:

| Field | Source |
|---|---|
| `triggered_rules` / `non_triggered_rules` | debug-log segment written during the stage (byte offset before/after), parsed as below |
| `interruption.rule_id` | the id of the last `(Rule: N)` block whose `Running (disruptive) action:` line named `deny`, `drop` or `redirect` (`redirert` in v3.0.16 is the same line misspelt); 0 when the intervention came from a body limit (`log` says "limit is marked to reject") |
| `interruption.action` | that action name; body limits report `deny` |
| `interruption.status` | `ModSecurityIntervention.status` |
| `no_interruption` | `msc_intervention` never reported `disruptive` |
| `log_contains` / `no_log_contains` | callback lines plus `ModSecurityIntervention.log` (v3 routes a denying rule's message there instead of the callback) |
| `expect_error` | `msc_rules_add_file` < 0 |

Debug-log parsing (`parse_debug_log(bytes) -> (triggered: set[int], disruptive: (rule_id, action) | None)`):
a `(Rule: N)` line with N ≠ 0 opens a block and sets `matched` to whether the line says
`Executing unconditional rule`; `Rule returned 1.`/`0.` sets `matched`; `(Rule: 0)` is a
chain member and keeps the current block (its `Rule returned` decides the chain); a
block is triggered if `matched` is true when the next block opens or the log ends. Lines
are split on the `[level] ` prefix with a regex anchored on the three bracketed fields.

## 5. Unit tier

Inputs are byte strings; each is Latin-1 encoded and sent with
`msc_append_request_body(buf, len)`, which is binary safe. v3 fills `REQUEST_BODY` for
any buffered body, so no `ctl:forceRequestBodyVariable` is needed; the request is a
`POST /` with `Content-Type: application/octet-stream`. Cases are grouped by
`(type, name, param)`, one rules set per group:

```
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 1048576
SecDebugLogLevel 0
# operators
SecRule REQUEST_BODY "@<op> <param>" "id:2,phase:2,pass,log,msg:'m'[,capture]"
SecRule TX:0 "@unconditionalMatch" "id:10,phase:2,pass,log,t:hexEncode,msg:'%{MATCHED_VAR}'"   # … TX:9 -> id:19, only when the case has re_groups
# transformations
SecRule REQUEST_BODY "@unconditionalMatch" "id:2,phase:2,pass,log,t:<name>,t:hexEncode,msg:'%{MATCHED_VAR}'"
```

Results are read from the error-log callback lines: `[id "2"]` present ⇒ matched;
`[msg "<hex>"]` decoded ⇒ transformation output (`%{MATCHED_VAR}` expands to the fully
transformed value; `t:hexEncode` makes it ASCII and keeps NUL bytes); `[id "1i"]`
lines give `TX:i` for `re_groups`, stopping at the first missing group. `ret` for
transformations is `output != input`.

`param` is inserted verbatim (as Latin-1 bytes): v3 keeps `\\` pairs and treats `\"` as
two characters, and no unit parameter contains `"`. Parameters with control characters
are skipped, as in the Coraza adapter. Operators or transformations the library does
not register are skipped at file level from a list in `test_conformance.py`, filled in
from the first run (expected: `fuzzyHash` and `geoLookup` without ssdeep/maxmind support).
`rx-pcre-extensions` cases run: v3.0.16 builds on PCRE2.

## 6. Known gaps

`gaps.load(path, "libmodsecurity v3")` returns `{test path: reason}` for rows whose
Engine cell names that engine. Gating is the Coraza rule: unlisted file ⇒ every subtest
must pass; listed file ⇒ failures logged as expected, and a listed file with no failure
fails with "known-gaps row is obsolete". The first run turns the v3 prediction rows
(default phase, SecDefaultAction phase, skipAfter missing marker, `\"` kept,
`ctl:forceRequestBodyVariable`) into verified rows or removes them, and adds rows for
divergences it uncovers; `compat/known-gaps.md` prose, `adapters/coraza/README.md`
("Adding another engine") and ADR-0023 are updated to name the second adapter.

## 7. CI

`.github/workflows/validate.yml` gains a job `libmodsecurity-adapter` on `ubuntu-latest`:

1. `apt-get install libpcre2-dev libxml2-dev libyajl-dev` (runtime libraries are needed
   on every run; the `-dev` packages are small and also cover a rebuild).
2. `actions/cache@v4` on `~/modsecurity` keyed `libmodsecurity-v3.0.16-${{ runner.os }}-${{ runner.arch }}`.
3. On a miss: `git clone --depth 1 -b v3.0.16 --recurse-submodules --shallow-submodules
   https://github.com/owasp-modsecurity/ModSecurity.git`, `./build.sh`, `./configure
   --prefix=$HOME/modsecurity --disable-doxygen-doc --disable-examples --without-lua
   --without-lmdb --without-ssdeep --without-curl --without-geoip --without-maxmind`,
   `make -j$(nproc)`, `make install`.
4. `astral-sh/setup-uv`, `uv sync`, then the unittest command with
   `MODSECURITY_LIB=$HOME/modsecurity/lib/libmodsecurity.so`.

The version is pinned in the workflow and named in the README; bumping it is a one-line
change plus a known-gaps review.

## 8. Errors and limits

- A profile that fails to load without `expect_error` is one failure for the file.
- An engine crash (segfault) cannot be caught from ctypes and aborts the run; none is
  known for v3.0.16 on this data. If one appears, that file is isolated in a subprocess.
- Timing: about 300 rule sets and 4,300 transactions for the unit tier plus 116 engine
  profiles with level-4 debug logging; expected well under two minutes.

## 9. Testing the adapter itself

`test_adapter.py`: debug-log parser on canned text (plain match, non-match, unconditional
rule, chain whose member fails, chain that matches, `deny` with status, `redirert`,
body-limit intervention); error-log `msg` hex extraction and `TX:i` collection; gaps
parsing with a multi-engine cell and the obsolete-row path; data loading and Latin-1
round trip; one real-engine smoke test (a rule set with a matching and a non-matching
rule, one operator case and one transformation case) that is skipped without
`MODSECURITY_LIB`.
