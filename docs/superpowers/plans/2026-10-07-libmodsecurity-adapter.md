# libmodsecurity v3 Reference Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the conformance data in `tests/` against libmodsecurity v3.0.16 through its C API, gated by `compat/known-gaps.md`, locally and in CI.

**Architecture:** A flat Python package `adapters/libmodsecurity/` (ctypes binding, data loaders, engine-tier driver that reads matched rules from the engine debug log, unit-tier driver that reads results from the error log, known-gaps gating, unittest entry point). CI builds libmodsecurity v3.0.16 from source once and caches it.

**Tech Stack:** Python ≥ 3.10, `ctypes` (stdlib), `pyyaml` (already a dev dependency), `unittest`, `uv`; libmodsecurity v3.0.16 built with libxml2, yajl, PCRE2.

**Spec:** `docs/superpowers/specs/2026-10-07-libmodsecurity-adapter-design.md`

## Global Constraints

- Python is always run through `uv` (`uv run …`); no new dependencies.
- Modules are imported flat (`import data`, `import mscapi`); run with `uv run python -m unittest discover -s adapters/libmodsecurity`.
- The library path comes from the `MODSECURITY_LIB` environment variable; everything that needs the engine is skipped when it is unset.
- Unit-tier strings are byte strings: Latin-1 encode before the engine, Latin-1 decode after (`tests/README.md`).
- Engine-tier `data` is UTF-8 text.
- Known-gaps gating: unlisted file ⇒ all pass; listed file ⇒ failures logged as expected; listed file with no failure ⇒ "known-gaps row is obsolete". Engine name in the table: `libmodsecurity v3`.
- Debug-log directives are appended **after** the profile's rules so they win; the debug level is 4.
- Every commit ends with the two attribution lines used throughout this repository.
- Local library for this session: `$SCRATCH/msc/install/lib/libmodsecurity.dylib` where `SCRATCH=/private/tmp/claude-502/-Users-fzipitria-Workspace-OWASP-seclang-spec/8a1fb3d7-5bb5-4bd0-a306-bd9f840a8595/scratchpad`.

## Review Focus

1. A debug-log line whose URI contains `] [4] ` must not be mis-split (Task 3 test `test_uri_with_brackets`).
2. A chain whose starter matches but whose member does not must not count the starter as triggered (Task 3 `test_chain_member_fails`).
3. A redirect's intervention must report action `redirect` although v3.0.16 logs `redirert` (Task 3 `test_redirect_typo`).
4. A transformation output that is empty must be read as `""`, not as "rule did not run" (Task 4 `test_messages_empty_output`).
5. A unit case without `param` must not emit a trailing space in the operator (Task 4 `test_unit_rules_without_param`).

---

### Task 1: Data loaders and known-gaps parsing

**Files:**
- Create: `adapters/libmodsecurity/data.py`, `adapters/libmodsecurity/gaps.py`
- Test: `adapters/libmodsecurity/test_adapter.py`

**Interfaces:**
- Produces: `data.repo_root() -> Path`; dataclasses `Input(method, uri, version, headers, data, remote_addr)`, `Response(status, headers, data)`, `Interruption(rule_id, action, status)`, `Output(triggered_rules, non_triggered_rules, interruption, no_interruption, log_contains, no_log_contains, expect_error)`, `Stage(input, response, output)`, `Test(title, stages)`, `Profile(path, requires, files, rules, tests)`, `UnitCase(type, name, param, input, output, ret, spec, re_groups)`; `data.load_profiles(root) -> list[Profile]`; `data.load_unit_cases(root) -> dict[str, list[UnitCase]]`; `data.latin1(s) -> bytes`; `data.byte_string(b) -> str`; `gaps.load_gaps(path, engine) -> dict[str, str]`.

- [ ] **Step 1: Write the failing tests**

```python
# adapters/libmodsecurity/test_adapter.py
import tempfile
import unittest
from pathlib import Path

import data
import gaps


class DataTests(unittest.TestCase):
    def test_repo_root_has_tests(self):
        self.assertTrue((data.repo_root() / "tests" / "engine").is_dir())

    def test_latin1_round_trip(self):
        self.assertEqual(data.latin1("aÿ\u0000"), b"a\xff\x00")
        self.assertEqual(data.byte_string(b"a\xff\x00"), "aÿ\u0000")

    def test_load_profiles_defaults(self):
        profiles = data.load_profiles(data.repo_root())
        self.assertGreater(len(profiles), 50)
        p = next(x for x in profiles if x.path == "tests/engine/directives/logging-directives-load.yaml")
        st = p.tests[0].stages[0]
        self.assertEqual(st.input.method, "GET")
        self.assertEqual(st.input.uri, "/?a=1")
        self.assertEqual(st.output.interruption.rule_id, 5200)
        self.assertEqual(st.output.interruption.action, "deny")
        self.assertIsNone(st.response)

    def test_load_unit_cases_param_presence(self):
        files = data.load_unit_cases(data.repo_root())
        rx = files["tests/unit/operators/rx.json"]
        self.assertEqual(rx[0].param, "test")
        self.assertEqual(rx[1].param, "")
        self.assertIsNone(rx[2].param)
        self.assertEqual(rx[0].re_groups, [])


class GapsTests(unittest.TestCase):
    TABLE = """# x
| Test | Engine | Behaviour today | Decided in |
|---|---|---|---|
| `tests/engine/a.yaml` | Coraza | one | ADR-1 |
| `tests/engine/b.yaml`, `tests/engine/c.yaml` | libmodsecurity v3, Coraza | two | ADR-2 |
| `tests/unit/d.json` | ModSecurity v2 | three | ADR-3 |
"""

    def test_rows_for_engine(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "k.md"
            p.write_text(self.TABLE)
            self.assertEqual(gaps.load_gaps(p, "libmodsecurity v3"),
                             {"tests/engine/b.yaml": "two", "tests/engine/c.yaml": "two"})
            self.assertEqual(set(gaps.load_gaps(p, "coraza")),
                             {"tests/engine/a.yaml", "tests/engine/b.yaml", "tests/engine/c.yaml"})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3`
Expected: `ModuleNotFoundError: No module named 'data'`

- [ ] **Step 3: Implement `data.py` and `gaps.py`**

```python
# adapters/libmodsecurity/data.py
"""Loaders for tests/engine and tests/unit; the dataclasses mirror tests/schema/*."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@dataclass
class Input:
    method: str = "GET"
    uri: str = "/"
    version: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    data: str = ""
    remote_addr: str = "127.0.0.1"


@dataclass
class Response:
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    data: str = ""


@dataclass
class Interruption:
    rule_id: int = 0
    action: str = ""
    status: int = 0


@dataclass
class Output:
    triggered_rules: list[int] = field(default_factory=list)
    non_triggered_rules: list[int] = field(default_factory=list)
    interruption: Interruption | None = None
    no_interruption: bool = False
    log_contains: str = ""
    no_log_contains: str = ""
    expect_error: bool = False


@dataclass
class Stage:
    input: Input
    response: Response | None
    output: Output


@dataclass
class Test:
    title: str
    stages: list[Stage]


@dataclass
class Profile:
    path: str  # relative to the repository root, POSIX separators
    requires: list[str]
    files: dict[str, str]
    rules: str
    tests: list[Test]


@dataclass
class UnitCase:
    type: str
    name: str
    param: str | None  # None when the case has no "param" key
    input: str
    output: str
    ret: int
    spec: str
    re_groups: list[str]


def _input(d: dict) -> Input:
    return Input(
        method=d.get("method") or "GET",
        uri=d.get("uri") or "/",
        version=d.get("version") or "HTTP/1.1",
        headers={str(k): str(v) for k, v in (d.get("headers") or {}).items()},
        data=d.get("data") or "",
        remote_addr=d.get("remote_addr") or "127.0.0.1",
    )


def _response(d: dict | None) -> Response | None:
    if d is None:
        return None
    return Response(status=d.get("status") or 200,
                    headers={str(k): str(v) for k, v in (d.get("headers") or {}).items()},
                    data=d.get("data") or "")


def _output(d: dict) -> Output:
    it = d.get("interruption")
    return Output(
        triggered_rules=list(d.get("triggered_rules") or []),
        non_triggered_rules=list(d.get("non_triggered_rules") or []),
        interruption=Interruption(it.get("rule_id", 0), it.get("action", ""), it.get("status", 0)) if it else None,
        no_interruption=bool(d.get("no_interruption", False)),
        log_contains=d.get("log_contains") or "",
        no_log_contains=d.get("no_log_contains") or "",
        expect_error=bool(d.get("expect_error", False)),
    )


def load_profiles(root: Path) -> list[Profile]:
    out = []
    for path in sorted((root / "tests" / "engine").rglob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        tests = [Test(t.get("test_title", ""),
                      [Stage(_input(s["stage"].get("input") or {}),
                             _response(s["stage"].get("response")),
                             _output(s["stage"].get("output") or {}))
                       for s in t.get("stages") or []])
                 for t in doc.get("tests") or []]
        out.append(Profile(path.relative_to(root).as_posix(), list(doc.get("requires") or []),
                           dict(doc.get("files") or {}), doc.get("rules") or "", tests))
    return out


def load_unit_cases(root: Path) -> dict[str, list[UnitCase]]:
    out = {}
    for path in sorted((root / "tests" / "unit").rglob("*.json")):
        cases = json.loads(path.read_text())
        out[path.relative_to(root).as_posix()] = [
            UnitCase(c["type"], c["name"], c.get("param"), c.get("input", ""), c.get("output", ""),
                     int(c.get("ret", 0)), c.get("spec", ""), list(c.get("re_groups") or []))
            for c in cases]
    return out


def latin1(s: str) -> bytes:
    """Byte string (one code point per byte) to bytes."""
    return s.encode("latin-1")


def byte_string(b: bytes) -> str:
    return b.decode("latin-1")
```

```python
# adapters/libmodsecurity/gaps.py
"""Rows of compat/known-gaps.md for one engine: {test path: behaviour today}."""
from __future__ import annotations

import re
from pathlib import Path

_PATH = re.compile(r"`(tests/[^`]+)`")


def load_gaps(path: Path, engine: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in Path(path).read_text().splitlines():
        if not line.startswith("| `tests/"):
            continue
        cells = line.strip("| ").split(" | ")
        if len(cells) < 3 or engine.lower() not in cells[1].lower():
            continue
        for p in _PATH.findall(cells[0]):
            out[p] = cells[2].strip()
    return out
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3`
Expected: `OK` with 5 tests.

- [ ] **Step 5: Commit**

```bash
git add adapters/libmodsecurity/data.py adapters/libmodsecurity/gaps.py adapters/libmodsecurity/test_adapter.py
git commit -m "feat(libmodsecurity): data loaders and known-gaps parsing"
```

---

### Task 2: ctypes binding

**Files:**
- Create: `adapters/libmodsecurity/mscapi.py`
- Test: `adapters/libmodsecurity/test_adapter.py` (append)

**Interfaces:**
- Produces: `mscapi.ENV = "MODSECURITY_LIB"`; `mscapi.LoadError(Exception)`; `class ModSecurity(path=None)` with `.log: list[bytes]` (error-log lines of the current transaction), `.version() -> str`, `.rules_from_file(path: str) -> RulesSet` (raises `LoadError`), `.transaction(rules) -> Transaction` (clears `.log`); `RulesSet.close()`; `Transaction` methods `connection(client, cport, server, sport)`, `uri(uri, method, version)`, `request_header(k, v)`, `process_request_headers()`, `append_request_body(b: bytes)`, `process_request_body()`, `response_header(k, v)`, `process_response_headers(status, proto)`, `append_response_body(b)`, `process_response_body()`, `process_logging()`, `intervention() -> dict | None` with keys `status`, `url`, `log` (bytes or None), `close()`.

- [ ] **Step 1: Write the failing test**

```python
# append to adapters/libmodsecurity/test_adapter.py
import os
import mscapi

needs_engine = unittest.skipUnless(os.environ.get(mscapi.ENV), f"{mscapi.ENV} not set")


@needs_engine
class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ms = mscapi.ModSecurity()

    def test_version(self):
        self.assertIn("ModSecurity v3", self.ms.version())

    def test_load_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.conf"
            p.write_text("SecRule ARGS\n")
            with self.assertRaises(mscapi.LoadError):
                self.ms.rules_from_file(str(p))

    def test_deny_intervention_and_log(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.conf"
            p.write_text('SecRuleEngine On\nSecRule ARGS:a "@streq 1" "id:7,phase:1,deny,status:418,log,msg:\'hit\'"\n')
            rules = self.ms.rules_from_file(str(p))
            tx = self.ms.transaction(rules)
            tx.connection("127.0.0.1", 12345, "127.0.0.1", 80)
            tx.uri("/?a=1", "GET", "1.1")
            tx.request_header("Host", "localhost")
            tx.process_request_headers()
            it = tx.intervention()
            tx.process_logging()
            tx.close()
            rules.close()
            self.assertEqual(it["status"], 418)
            self.assertIn(b'[id "7"]', it["log"])
            self.assertIsNone(it["url"])
```

- [ ] **Step 2: Run to verify failure**

Run: `MODSECURITY_LIB=$SCRATCH/msc/install/lib/libmodsecurity.dylib uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3`
Expected: `ModuleNotFoundError: No module named 'mscapi'`

- [ ] **Step 3: Implement**

```python
# adapters/libmodsecurity/mscapi.py
"""ctypes binding for the parts of the libmodsecurity C API the adapter uses."""
from __future__ import annotations

import ctypes
import os
from ctypes import CFUNCTYPE, POINTER, Structure, byref, c_char_p, c_int, c_size_t, c_void_p

ENV = "MODSECURITY_LIB"


class LoadError(Exception):
    """The rules file was rejected by the engine."""


class _Intervention(Structure):
    _fields_ = [("status", c_int), ("pause", c_int), ("url", c_char_p), ("log", c_char_p), ("disruptive", c_int)]


_LOG_CB = CFUNCTYPE(None, c_void_p, c_void_p)

_SIGNATURES = {
    "msc_init": (c_void_p, []),
    "msc_who_am_i": (c_char_p, [c_void_p]),
    "msc_set_log_cb": (None, [c_void_p, _LOG_CB]),
    "msc_create_rules_set": (c_void_p, []),
    "msc_rules_add_file": (c_int, [c_void_p, c_char_p, POINTER(c_char_p)]),
    "msc_rules_cleanup": (c_int, [c_void_p]),
    "msc_new_transaction": (c_void_p, [c_void_p, c_void_p, c_void_p]),
    "msc_process_connection": (c_int, [c_void_p, c_char_p, c_int, c_char_p, c_int]),
    "msc_process_uri": (c_int, [c_void_p, c_char_p, c_char_p, c_char_p]),
    "msc_add_request_header": (c_int, [c_void_p, c_char_p, c_char_p]),
    "msc_process_request_headers": (c_int, [c_void_p]),
    "msc_append_request_body": (c_int, [c_void_p, c_char_p, c_size_t]),
    "msc_process_request_body": (c_int, [c_void_p]),
    "msc_add_response_header": (c_int, [c_void_p, c_char_p, c_char_p]),
    "msc_process_response_headers": (c_int, [c_void_p, c_int, c_char_p]),
    "msc_append_response_body": (c_int, [c_void_p, c_char_p, c_size_t]),
    "msc_process_response_body": (c_int, [c_void_p]),
    "msc_process_logging": (c_int, [c_void_p]),
    "msc_intervention": (c_int, [c_void_p, POINTER(_Intervention)]),
    "msc_intervention_cleanup": (None, [POINTER(_Intervention)]),
    "msc_transaction_cleanup": (None, [c_void_p]),
}


def _b(s: str | bytes) -> bytes:
    return s if isinstance(s, bytes) else s.encode("utf-8")


class ModSecurity:
    """One engine instance per process. `log` collects error-log lines; `transaction()` clears it."""

    def __init__(self, path: str | None = None):
        path = path or os.environ.get(ENV)
        if not path:
            raise RuntimeError(f"{ENV} is not set: point it at libmodsecurity.so/.dylib")
        self.lib = ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL)
        for name, (res, args) in _SIGNATURES.items():
            fn = getattr(self.lib, name)
            fn.restype, fn.argtypes = res, args
        self.log: list[bytes] = []
        self._cb = _LOG_CB(self._on_log)  # keep a reference or ctypes frees the trampoline
        self.handle = self.lib.msc_init()
        self.lib.msc_set_log_cb(self.handle, self._cb)

    def _on_log(self, _data, msg):
        self.log.append(ctypes.string_at(msg))

    def version(self) -> str:
        return self.lib.msc_who_am_i(self.handle).decode()

    def rules_from_file(self, path: str) -> "RulesSet":
        h = self.lib.msc_create_rules_set()
        err = c_char_p()
        if self.lib.msc_rules_add_file(h, _b(path), byref(err)) < 0:
            msg = (err.value or b"unknown error").decode("utf-8", "replace")
            self.lib.msc_rules_cleanup(h)
            raise LoadError(msg)
        return RulesSet(self, h)

    def transaction(self, rules: "RulesSet") -> "Transaction":
        self.log.clear()
        return Transaction(self, rules)


class RulesSet:
    def __init__(self, ms: ModSecurity, handle):
        self.ms, self.h = ms, handle

    def close(self):
        if self.h:
            self.ms.lib.msc_rules_cleanup(self.h)
            self.h = None


class Transaction:
    def __init__(self, ms: ModSecurity, rules: RulesSet):
        self.lib = ms.lib
        self.h = self.lib.msc_new_transaction(ms.handle, rules.h, None)

    def connection(self, client: str, cport: int, server: str, sport: int):
        self.lib.msc_process_connection(self.h, _b(client), cport, _b(server), sport)

    def uri(self, uri: str, method: str, version: str):
        self.lib.msc_process_uri(self.h, _b(uri), _b(method), _b(version))

    def request_header(self, k: str, v: str):
        self.lib.msc_add_request_header(self.h, _b(k), _b(v))

    def process_request_headers(self):
        self.lib.msc_process_request_headers(self.h)

    def append_request_body(self, b: bytes):
        self.lib.msc_append_request_body(self.h, b, len(b))

    def process_request_body(self):
        self.lib.msc_process_request_body(self.h)

    def response_header(self, k: str, v: str):
        self.lib.msc_add_response_header(self.h, _b(k), _b(v))

    def process_response_headers(self, status: int, proto: str):
        self.lib.msc_process_response_headers(self.h, status, _b(proto))

    def append_response_body(self, b: bytes):
        self.lib.msc_append_response_body(self.h, b, len(b))

    def process_response_body(self):
        self.lib.msc_process_response_body(self.h)

    def process_logging(self):
        self.lib.msc_process_logging(self.h)

    def intervention(self) -> dict | None:
        """The pending disruptive intervention, reported once by the engine, or None."""
        it = _Intervention()
        if not self.lib.msc_intervention(self.h, byref(it)):
            return None
        out = {"status": it.status, "url": it.url, "log": it.log}  # c_char_p fields are copied
        self.lib.msc_intervention_cleanup(byref(it))
        return out

    def close(self):
        if self.h:
            self.lib.msc_transaction_cleanup(self.h)
            self.h = None
```

- [ ] **Step 4: Run to verify pass (with and without the engine)**

Run: `MODSECURITY_LIB=$SCRATCH/msc/install/lib/libmodsecurity.dylib uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3`
Expected: `OK`, 8 tests.
Run: `uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3`
Expected: `OK (skipped=3)`.

- [ ] **Step 5: Commit**

```bash
git add adapters/libmodsecurity/mscapi.py adapters/libmodsecurity/test_adapter.py
git commit -m "feat(libmodsecurity): ctypes binding for the C API"
```

---

### Task 3: Engine tier

**Files:**
- Create: `adapters/libmodsecurity/engine_tier.py`
- Test: `adapters/libmodsecurity/test_adapter.py` (append)

**Interfaces:**
- Consumes: Task 1 dataclasses; Task 2 `ModSecurity`, `RulesSet`, `Transaction`, `LoadError`.
- Produces: `engine_tier.parse_debug_log(data: bytes) -> tuple[set[int], tuple[int, str] | None]`; `@dataclass Observed(triggered: set[int], interruption: Interruption | None, log: str)`; `engine_tier.build_rules(ms, profile, workdir: Path) -> tuple[RulesSet, Path]` (rules set and debug-log path; raises `LoadError`); `engine_tier.run_stage(ms, rules, debug_path, stage) -> Observed`; `engine_tier.check_stage(observed, output) -> list[str]`.

- [ ] **Step 1: Write the failing tests**

```python
# append to adapters/libmodsecurity/test_adapter.py
import engine_tier
from data import Interruption, Output

L = b"[1.2] [/?a=1] [4] "


def dbg(*texts):
    return b"\n".join(L + t for t in texts) + b"\n"


class DebugLogTests(unittest.TestCase):
    def test_match_and_non_match(self):
        t, d = engine_tier.parse_debug_log(dbg(
            b'(Rule: 1) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b'(Rule: 2) Executing operator "StrEq" with param "9" against ARGS:a.', b"Rule returned 0."))
        self.assertEqual(t, {1})
        self.assertIsNone(d)

    def test_unconditional_rule(self):
        t, _ = engine_tier.parse_debug_log(dbg(b"(Rule: 3) Executing unconditional rule..."))
        self.assertEqual(t, {3})

    def test_chain_member_fails(self):
        t, _ = engine_tier.parse_debug_log(dbg(
            b'(Rule: 4) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Executing chained rule.",
            b'(Rule: 0) Executing operator "StrEq" with param "2" against ARGS:b.', b"Rule returned 0.",
            b'(Rule: 5) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1."))
        self.assertEqual(t, {5})

    def test_chain_matches(self):
        t, _ = engine_tier.parse_debug_log(dbg(
            b'(Rule: 4) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Executing chained rule.",
            b'(Rule: 0) Executing operator "StrEq" with param "2" against ARGS:b.', b"Rule returned 1."))
        self.assertEqual(t, {4})

    def test_deny_attribution(self):
        t, d = engine_tier.parse_debug_log(dbg(
            b'(Rule: 20) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Running (disruptive)     action: deny."))
        self.assertEqual((t, d), ({20}, (20, "deny")))

    def test_redirect_typo(self):
        _, d = engine_tier.parse_debug_log(dbg(
            b'(Rule: 30) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Running (disruptive)     action: redirert."))
        self.assertEqual(d, (30, "redirect"))

    def test_pass_is_not_disruptive(self):
        _, d = engine_tier.parse_debug_log(dbg(
            b'(Rule: 1) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Running (disruptive)     action: pass."))
        self.assertIsNone(d)

    def test_uri_with_brackets(self):
        line = b"[1.2] [/x] [9] y] [4] z\n" + b"[1.2] [/?a=1] [4] (Rule: 8) Executing unconditional rule...\n"
        t, _ = engine_tier.parse_debug_log(line)
        self.assertEqual(t, {8})


class CheckStageTests(unittest.TestCase):
    def test_messages(self):
        o = engine_tier.Observed({1}, Interruption(1, "deny", 403), "ModSecurity: Warning x")
        self.assertEqual(engine_tier.check_stage(o, Output(triggered_rules=[1], interruption=Interruption(1, "deny", 403), log_contains="Warning")), [])
        msgs = engine_tier.check_stage(o, Output(triggered_rules=[2], non_triggered_rules=[1], no_interruption=True, no_log_contains="Warning"))
        self.assertEqual(len(msgs), 4)
        msgs = engine_tier.check_stage(engine_tier.Observed(set(), None, ""), Output(interruption=Interruption(1, "deny", 0)))
        self.assertEqual(len(msgs), 1)


@needs_engine
class EngineSmokeTests(unittest.TestCase):
    def test_stage_round_trip(self):
        ms = mscapi.ModSecurity()
        profile = data.Profile("x", [], {"inc.conf": 'SecRule ARGS:a "@streq 1" "id:2,phase:1,pass,nolog"\n'},
                               'SecRuleEngine On\nInclude inc.conf\nSecRule ARGS:a "@streq 1" "id:1,phase:2,deny,status:418,log,msg:\'hit\'"\n'
                               'SecRule ARGS:a "@streq 9" "id:3,phase:1,pass"\n', [])
        with tempfile.TemporaryDirectory() as d:
            rules, debug = engine_tier.build_rules(ms, profile, Path(d))
            st = data.Stage(data.Input(uri="/?a=1"), None, Output())
            o = engine_tier.run_stage(ms, rules, debug, st)
            o2 = engine_tier.run_stage(ms, rules, debug, data.Stage(data.Input(uri="/?a=9"), None, Output()))
            rules.close()
        self.assertEqual(o.triggered, {1, 2})
        self.assertEqual(o.interruption, Interruption(1, "deny", 418))
        self.assertIn("hit", o.log)
        self.assertEqual(o2.triggered, {3})
        self.assertIsNone(o2.interruption)
```

- [ ] **Step 2: Run to verify failure**

Run: `MODSECURITY_LIB=$SCRATCH/msc/install/lib/libmodsecurity.dylib uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3`
Expected: `ModuleNotFoundError: No module named 'engine_tier'`

- [ ] **Step 3: Implement**

```python
# adapters/libmodsecurity/engine_tier.py
"""Engine-tier driver: one rules set per profile, one transaction per stage.

Matched rules (including nolog ones) are read from the engine debug log at level 4; the
intervention from msc_intervention plus the "(disruptive) action" debug line.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from data import Interruption, Output, Profile, Stage
from mscapi import ModSecurity, RulesSet

_LINE = re.compile(rb"^\[[^\]]*\] \[.*?\] \[(\d+)\] (.*)$")
_BLOCK = re.compile(rb"^\(Rule: (\d+)\) ")
_ACTIONS = {b"deny": "deny", b"drop": "drop", b"redirect": "redirect", b"redirert": "redirect"}  # v3.0.16 misspells redirect


def parse_debug_log(data: bytes) -> tuple[set[int], tuple[int, str] | None]:
    """Triggered rule ids and the (rule id, action) of the disruptive action, if any.

    A "(Rule: N)" line with N != 0 opens a block; "(Rule: 0)" is a chain member and keeps
    the block open, so its "Rule returned" decides the chain; "Executing unconditional
    rule" counts as a match. A block is triggered when it is still matched at the next
    block or at the end.
    """
    triggered: set[int] = set()
    disruptive = None
    current, matched = None, False
    for line in data.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        text = m.group(2)
        b = _BLOCK.match(text)
        if b:
            rid = int(b.group(1))
            if rid:
                if current is not None and matched:
                    triggered.add(current)
                current, matched = rid, b"Executing unconditional rule" in text
        elif text == b"Rule returned 1.":
            matched = True
        elif text == b"Rule returned 0.":
            matched = False
        elif text.startswith(b"Running (disruptive)") and current is not None:
            name = text.rsplit(b"action: ", 1)[-1].rstrip(b".")
            if name in _ACTIONS:
                disruptive = (current, _ACTIONS[name])
    if current is not None and matched:
        triggered.add(current)
    return triggered, disruptive


@dataclass
class Observed:
    triggered: set[int]
    interruption: Interruption | None
    log: str


def build_rules(ms: ModSecurity, profile: Profile, workdir: Path) -> tuple[RulesSet, Path]:
    """Write files: and rules.conf under workdir and load it; raises LoadError.

    The debug-log directives are appended so they override any the profile sets.
    """
    for name, content in profile.files.items():
        p = workdir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    debug = workdir / "debug.log"
    conf = workdir / "rules.conf"
    conf.write_text(profile.rules + f"\nSecDebugLog {debug}\nSecDebugLogLevel 4\n")
    return ms.rules_from_file(str(conf)), debug


def run_stage(ms: ModSecurity, rules: RulesSet, debug_path: Path, stage: Stage) -> Observed:
    start = debug_path.stat().st_size if debug_path.exists() else 0
    tx = ms.transaction(rules)
    it = None
    try:
        i = stage.input
        tx.connection(i.remote_addr, 12345, "127.0.0.1", 80)
        tx.uri(i.uri, i.method, i.version.removeprefix("HTTP/"))
        for k, v in i.headers.items():
            tx.request_header(k, v)
        if not any(k.lower() == "host" for k in i.headers):
            tx.request_header("Host", "localhost")
        tx.process_request_headers()
        it = tx.intervention()
        if it is None:
            if i.data:
                tx.append_request_body(i.data.encode("utf-8"))  # engine-tier data is UTF-8 text
            tx.process_request_body()
            it = tx.intervention()
        if it is None and stage.response is not None:
            r = stage.response
            for k, v in r.headers.items():
                tx.response_header(k, v)
            tx.process_response_headers(r.status, "HTTP 1.1")
            it = tx.intervention()
            if it is None:
                if r.data:
                    tx.append_response_body(r.data.encode("utf-8"))
                tx.process_response_body()
                it = tx.intervention()
        tx.process_logging()
        it = it or tx.intervention()
        log = list(ms.log)
    finally:
        tx.close()
    segment = debug_path.read_bytes()[start:] if debug_path.exists() else b""
    triggered, disruptive = parse_debug_log(segment)
    interruption = None
    if it is not None:
        rule_id, action = disruptive if disruptive else (0, "deny")  # no rule block: a body limit
        interruption = Interruption(rule_id, action, it["status"])
        if it["log"]:
            log.append(it["log"])  # v3 puts a denying rule's message here, not in the callback
    return Observed(triggered, interruption, b"\n".join(log).decode("utf-8", "replace"))


def check_stage(o: Observed, want: Output) -> list[str]:
    """Every mismatch in words; empty when the stage passes."""
    msgs = []
    for rid in want.triggered_rules:
        if rid not in o.triggered:
            msgs.append(f"rule {rid} expected to trigger; triggered={sorted(o.triggered)}")
    for rid in want.non_triggered_rules:
        if rid in o.triggered:
            msgs.append(f"rule {rid} expected not to trigger")
    if want.no_interruption and o.interruption is not None:
        msgs.append(f"unexpected interruption: rule {o.interruption.rule_id} {o.interruption.action} {o.interruption.status}")
    if want.interruption is not None:
        w = want.interruption
        if o.interruption is None:
            msgs.append(f"expected interruption by rule {w.rule_id} ({w.action}), none observed")
        else:
            if o.interruption.rule_id != w.rule_id:
                msgs.append(f"interruption by rule {o.interruption.rule_id}, expected {w.rule_id}")
            if o.interruption.action != w.action:
                msgs.append(f"interruption action {o.interruption.action!r}, expected {w.action!r}")
            if w.status and o.interruption.status != w.status:
                msgs.append(f"interruption status {o.interruption.status}, expected {w.status}")
    if want.log_contains and want.log_contains not in o.log:
        msgs.append(f"log does not contain {want.log_contains!r}")
    if want.no_log_contains and want.no_log_contains in o.log:
        msgs.append(f"log contains {want.no_log_contains!r}")
    return msgs
```

- [ ] **Step 4: Run to verify pass**

Run: `MODSECURITY_LIB=$SCRATCH/msc/install/lib/libmodsecurity.dylib uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3`
Expected: `OK`, 18 tests. If `test_stage_round_trip` fails on `{1, 2}` because `Include inc.conf` did not resolve relative to `rules.conf`, that is an engine fact to record: change `build_rules` to also pass the absolute path by rewriting nothing and instead `os.chdir` is **not** acceptable; ledger the finding and make the smoke test use an absolute Include path while `build_rules` keeps writing files beside the rules file (profiles with relative Includes then show up in the first run and get rows or spec fixes).

- [ ] **Step 5: Commit**

```bash
git add adapters/libmodsecurity/engine_tier.py adapters/libmodsecurity/test_adapter.py
git commit -m "feat(libmodsecurity): engine-tier driver reading matches from the debug log"
```

---

### Task 4: Unit tier

**Files:**
- Create: `adapters/libmodsecurity/unit_tier.py`
- Test: `adapters/libmodsecurity/test_adapter.py` (append)

**Interfaces:**
- Consumes: Task 1 `UnitCase`, `latin1`, `byte_string`; Task 2 `ModSecurity`, `RulesSet`.
- Produces: `unit_tier.unit_rules(case) -> bytes`; `unit_tier.messages(lines: list[bytes]) -> dict[int, bytes]` (rule id → `[msg]` content); `@dataclass UnitResult(matched: bool, output: str, groups: list[str])`; `unit_tier.load_rules(ms, case, workdir: Path) -> RulesSet` (raises `LoadError`); `unit_tier.run_unit(ms, rules, case) -> UnitResult`; `unit_tier.check_unit(case, result) -> list[str]`; `unit_tier.group_key(case) -> tuple`.

- [ ] **Step 1: Write the failing tests**

```python
# append to adapters/libmodsecurity/test_adapter.py
import unit_tier
from data import UnitCase


def case(**kw):
    base = dict(type="op", name="rx", param=None, input="", output="", ret=0, spec="", re_groups=[])
    base.update(kw)
    return UnitCase(**base)


class UnitRulesTests(unittest.TestCase):
    def test_unit_rules_without_param(self):
        r = unit_tier.unit_rules(case(name="validateUrlEncoding"))
        self.assertIn(b'SecRule REQUEST_BODY "@validateUrlEncoding" "id:2,phase:2,pass,log,msg:\'m\'"\n', r)

    def test_unit_rules_param_is_bytes_verbatim(self):
        r = unit_tier.unit_rules(case(param="a\\\"bé"))
        self.assertIn(b'"@rx a\\"b\xe9"', r)

    def test_unit_rules_capture_adds_tx_rules(self):
        r = unit_tier.unit_rules(case(param="(a)", re_groups=["a", "a"]))
        self.assertIn(b",capture", r)
        self.assertIn(b'SecRule TX:0 "@unconditionalMatch" "id:10,phase:2,pass,log,t:hexEncode,msg:\'%{MATCHED_VAR}\'"', r)
        self.assertIn(b'SecRule TX:9 "@unconditionalMatch" "id:19,', r)

    def test_unit_rules_transformation(self):
        r = unit_tier.unit_rules(case(type="tfn", name="lowercase"))
        self.assertIn(b'"id:2,phase:2,pass,log,t:lowercase,t:hexEncode,msg:\'%{MATCHED_VAR}\'"', r)

    def test_messages_empty_output(self):
        lines = [b'ModSecurity: Warning. Matched x [file "a"] [id "2"] [rev ""] [msg ""] [data ""]',
                 b'ModSecurity: Warning. Matched x [id "10"] [msg "4100"]']
        self.assertEqual(unit_tier.messages(lines), {2: b"", 10: b"4100"})

    def test_check_unit(self):
        c = case(type="tfn", name="lowercase", input="A", output="a", ret=1)
        self.assertEqual(unit_tier.check_unit(c, unit_tier.UnitResult(True, "a", [])), [])
        self.assertEqual(len(unit_tier.check_unit(c, unit_tier.UnitResult(True, "A", []))), 1)
        self.assertEqual(len(unit_tier.check_unit(c, unit_tier.UnitResult(False, "", []))), 1)
        o = case(param="(a)(b)", input="xab", ret=1, re_groups=["ab", "a", "b"])
        self.assertEqual(unit_tier.check_unit(o, unit_tier.UnitResult(True, "", ["ab", "a", "b"])), [])
        self.assertEqual(len(unit_tier.check_unit(o, unit_tier.UnitResult(True, "", ["ab", "a"]))), 1)
        self.assertEqual(len(unit_tier.check_unit(o, unit_tier.UnitResult(False, "", []))), 2)


@needs_engine
class UnitSmokeTests(unittest.TestCase):
    def run_case(self, c):
        ms = mscapi.ModSecurity()
        with tempfile.TemporaryDirectory() as d:
            rules = unit_tier.load_rules(ms, c, Path(d))
            try:
                return unit_tier.run_unit(ms, rules, c)
            finally:
                rules.close()

    def test_operator_with_groups(self):
        r = self.run_case(case(param="^(A)(.)", input="AbC\u0000ÿ", ret=1, re_groups=["Ab", "A", "b"]))
        self.assertTrue(r.matched)
        self.assertEqual(r.groups, ["Ab", "A", "b"])
        self.assertFalse(self.run_case(case(param="zzz", input="abc")).matched)

    def test_transformation_output_with_nul(self):
        r = self.run_case(case(type="tfn", name="lowercase", input="AbC\u0000ÿ" + "x" * 300))
        self.assertTrue(r.matched)
        self.assertEqual(r.output, "abc\u0000ÿ" + "x" * 300)
        empty = self.run_case(case(type="tfn", name="lowercase", input=""))
        self.assertTrue(empty.matched)
        self.assertEqual(empty.output, "")
```

- [ ] **Step 2: Run to verify failure**

Run: `MODSECURITY_LIB=$SCRATCH/msc/install/lib/libmodsecurity.dylib uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3`
Expected: `ModuleNotFoundError: No module named 'unit_tier'`

- [ ] **Step 3: Implement**

```python
# adapters/libmodsecurity/unit_tier.py
"""Unit-tier driver: one rules set per (type, name, param), one transaction per case.

Results come from the error log: the wrapped rule carries `log`; for transformations
`msg:'%{MATCHED_VAR}'` after `t:hexEncode` carries the full transformed value as hex,
and one `TX:i` rule per capture group (ids 10..19) does the same for re_groups.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from data import UnitCase, byte_string, latin1
from mscapi import ModSecurity, RulesSet

_HEAD = b"SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 1048576\nSecDebugLogLevel 0\n"
_TX_RULE = b"SecRule TX:%d \"@unconditionalMatch\" \"id:%d,phase:2,pass,log,t:hexEncode,msg:'%%{MATCHED_VAR}'\"\n"
_ID = re.compile(rb'\[id "(\d+)"\]')
_MSG = re.compile(rb'\[msg "([^"]*)"\]')


def group_key(c: UnitCase) -> tuple:
    return (c.type, c.name, c.param, bool(c.re_groups))


def unit_rules(c: UnitCase) -> bytes:
    """The rules set text for a case, as bytes (the param is a Latin-1 byte string, inserted verbatim)."""
    if c.type == "op":
        op = b"@" + c.name.encode()
        if c.param is not None:
            op += b" " + latin1(c.param)
        capture = b",capture" if c.re_groups else b""
        rules = _HEAD + b'SecRule REQUEST_BODY "' + op + b"\" \"id:2,phase:2,pass,log,msg:'m'" + capture + b'"\n'
        if c.re_groups:
            rules += b"".join(_TX_RULE % (i, 10 + i) for i in range(10))
        return rules
    return _HEAD + b'SecRule REQUEST_BODY "@unconditionalMatch" "id:2,phase:2,pass,log,t:' + c.name.encode() + b",t:hexEncode,msg:'%{MATCHED_VAR}'\"\n"


def messages(lines: list[bytes]) -> dict[int, bytes]:
    """Rule id -> [msg "..."] content for every error-log line that names a rule."""
    out = {}
    for line in lines:
        m = _ID.search(line)
        if m:
            msg = _MSG.search(line)
            out[int(m.group(1))] = msg.group(1) if msg else b""
    return out


@dataclass
class UnitResult:
    matched: bool = False
    output: str = ""
    groups: list[str] = field(default_factory=list)


def load_rules(ms: ModSecurity, c: UnitCase, workdir: Path) -> RulesSet:
    conf = workdir / "unit.conf"
    conf.write_bytes(unit_rules(c))
    return ms.rules_from_file(str(conf))


def run_unit(ms: ModSecurity, rules: RulesSet, c: UnitCase) -> UnitResult:
    tx = ms.transaction(rules)
    try:
        tx.connection("127.0.0.1", 12345, "127.0.0.1", 80)
        tx.uri("/", "POST", "1.1")
        tx.request_header("Host", "localhost")
        tx.request_header("Content-Type", "application/octet-stream")
        tx.process_request_headers()
        tx.append_request_body(latin1(c.input))
        tx.process_request_body()
        tx.process_logging()
        msgs = messages(ms.log)
    finally:
        tx.close()
    r = UnitResult(matched=2 in msgs)
    if c.type == "tfn" and r.matched:
        r.output = byte_string(bytes.fromhex(msgs[2].decode()))
    for i in range(10):
        if 10 + i not in msgs:
            break
        r.groups.append(byte_string(bytes.fromhex(msgs[10 + i].decode())))
    return r


def check_unit(c: UnitCase, r: UnitResult) -> list[str]:
    """Every mismatch in words; empty when the case passes."""
    msgs = []
    if c.type == "op":
        if r.matched != (c.ret == 1):
            msgs.append(f"@{c.name} {c.param!r} on {c.input!r}: matched={r.matched}, expected ret={c.ret}")
        for i, g in enumerate(c.re_groups):
            if i >= len(r.groups) or r.groups[i] != g:
                got = r.groups[i] if i < len(r.groups) else "<none>"
                msgs.append(f"@{c.name} {c.param!r} on {c.input!r}: group {i} = {got!r}, expected {g!r}")
                break
    elif not r.matched:
        msgs.append(f"t:{c.name} on {c.input!r}: rule did not run")
    elif r.output != c.output:
        msgs.append(f"t:{c.name} on {c.input!r}: output {r.output!r}, expected {c.output!r}")
    return msgs
```

- [ ] **Step 4: Run to verify pass**

Run: `MODSECURITY_LIB=$SCRATCH/msc/install/lib/libmodsecurity.dylib uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3`
Expected: `OK`, 26 tests.

- [ ] **Step 5: Commit**

```bash
git add adapters/libmodsecurity/unit_tier.py adapters/libmodsecurity/test_adapter.py
git commit -m "feat(libmodsecurity): unit-tier driver reading results from the error log"
```

---

### Task 5: Conformance entry point, first run, known-gaps triage, README

**Files:**
- Create: `adapters/libmodsecurity/test_conformance.py`, `adapters/libmodsecurity/README.md`
- Modify: `compat/known-gaps.md` (rows and intro), `adapters/coraza/README.md` ("Adding another engine")

**Interfaces:**
- Consumes: everything above; `gaps.load_gaps(path, "libmodsecurity v3")`.
- Produces: the CI command `MODSECURITY_LIB=… uv run python -m unittest discover -s adapters/libmodsecurity`.

- [ ] **Step 1: Write the entry point**

```python
# adapters/libmodsecurity/test_conformance.py
"""Runs tests/engine and tests/unit against libmodsecurity, gated by compat/known-gaps.md.

Gating (ADR-0023): a file without a known-gaps row for this engine must pass entirely; a
file with a row may fail (failures are printed as expected); a file with a row that passes
entirely fails with "known-gaps row is obsolete".
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

import data
import engine_tier
import gaps
import mscapi
import unit_tier

ENGINE = "libmodsecurity v3"
# Extended anchors this engine implements; profiles requiring anything else are skipped.
IMPLEMENTED = {"05-variables.md#persistent-collections"}
# Extended/Deprecated features the library does not register; their files are skipped.
UNSUPPORTED_OPERATORS: set[str] = set()
UNSUPPORTED_TRANSFORMATIONS: set[str] = set()
UNSUPPORTED_ANCHORS: set[str] = set()

MS: mscapi.ModSecurity | None = None


def setUpModule():
    global MS
    if not os.environ.get(mscapi.ENV):
        raise unittest.SkipTest(f"{mscapi.ENV} not set")
    MS = mscapi.ModSecurity()


def run_profile(p: data.Profile) -> list[str]:
    expect_error = any(st.output.expect_error for t in p.tests for st in t.stages)
    with tempfile.TemporaryDirectory() as d:
        try:
            rules, debug = engine_tier.build_rules(MS, p, Path(d))
        except mscapi.LoadError as e:
            return [] if expect_error else [f"configuration failed to load: {e}"]
        try:
            if expect_error:
                return ["configuration loaded but expect_error was set"]
            failures = []
            for t in p.tests:
                for i, st in enumerate(t.stages, 1):
                    o = engine_tier.run_stage(MS, rules, debug, st)
                    failures += [f"{t.title} / stage {i}: {m}" for m in engine_tier.check_stage(o, st.output)]
            return failures
        finally:
            rules.close()


def has_control_chars(s: str | None) -> bool:
    return bool(s) and any(ord(ch) < 0x20 for ch in s)


def run_unit_file(cases: list[data.UnitCase]) -> list[str]:
    failures = []
    with tempfile.TemporaryDirectory() as d:
        loaded: dict[tuple, mscapi.RulesSet | None] = {}
        try:
            for c in cases:
                if has_control_chars(c.param):
                    continue  # a control character cannot be written inside a directive argument
                key = unit_tier.group_key(c)
                if key not in loaded:
                    try:
                        loaded[key] = unit_tier.load_rules(MS, c, Path(d))
                    except mscapi.LoadError as e:
                        loaded[key] = None
                        failures.append(f"@{c.name} {c.param!r}: rule failed to load: {e}")
                rules = loaded[key]
                if rules is None:
                    continue
                failures += unit_tier.check_unit(c, unit_tier.run_unit(MS, rules, c))
        finally:
            for r in loaded.values():
                if r is not None:
                    r.close()
    return failures


class Gated(unittest.TestCase):
    def report(self, path: str, known: dict[str, str], failures: list[str]):
        reason = known.get(path)
        if reason is not None:
            if not failures:
                self.fail(f"known-gaps row is obsolete: remove the row for {path} ({reason})")
            for f in failures:
                print(f"expected (known gap: {reason}): {path}: {f}", file=sys.stderr)
        elif failures:
            self.fail("\n".join(failures))


class TestEngine(Gated):
    def test_profiles(self):
        root = data.repo_root()
        known = gaps.load_gaps(root / "compat" / "known-gaps.md", ENGINE)
        for p in data.load_profiles(root):
            with self.subTest(p.path):
                missing = [r for r in p.requires if r not in IMPLEMENTED]
                if missing:
                    self.skipTest("requires " + missing[0])
                self.report(p.path, known, run_profile(p))


class TestUnit(Gated):
    def test_files(self):
        root = data.repo_root()
        known = gaps.load_gaps(root / "compat" / "known-gaps.md", ENGINE)
        for path, cases in data.load_unit_cases(root).items():
            with self.subTest(path):
                first = cases[0] if cases else None
                if first and first.type == "op" and first.name in UNSUPPORTED_OPERATORS:
                    self.skipTest("operator not implemented by libmodsecurity (Extended)")
                if first and first.type == "tfn" and first.name in UNSUPPORTED_TRANSFORMATIONS:
                    self.skipTest("transformation not implemented by libmodsecurity (Extended)")
                if first and first.spec in UNSUPPORTED_ANCHORS:
                    self.skipTest("Extended feature not implemented: " + first.spec)
                self.report(path, known, run_unit_file(cases))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: First run; save the output**

Run: `MODSECURITY_LIB=$SCRATCH/msc/install/lib/libmodsecurity.dylib uv run python -m unittest discover -s adapters/libmodsecurity -p 'test_conformance.py' -v > $SCRATCH/v3run1.txt 2>&1; grep -c "FAIL\|ERROR" $SCRATCH/v3run1.txt; grep -n "obsolete" $SCRATCH/v3run1.txt | head`
Expected: a list of failing subtests (unknown count) and possibly obsolete rows among the five v3 prediction rows (`default-phase`, `default-action-no-phase`, `skipafter-missing-marker`, `quoted-arguments`, `no-processor` + `ctl-options`).

- [ ] **Step 3: Triage every failure, one of three ways**

For each failing file read the failure text and the engine source under
`/Users/fzipitria/Workspace/OWASP/modsecurity/modsecurity/src` (branch v3, tag v3.0.16) to classify:

1. **Engine divergence** (the spec is right, v3 does something else): add a row to
   `compat/known-gaps.md` in the existing format
   `| \`tests/...\` | libmodsecurity v3 | <behaviour, with the source file> | <spec anchor or ADR> |`,
   or extend an existing row's Engine cell (`libmodsecurity v3, Coraza`).
2. **Specification or test defect** (v3 and the surveyed sources agree against the test):
   fix the spec/test, run `uv run python tools/validate.py` and the Coraza adapter
   (`cd adapters/coraza && go test ./...`) to confirm both engines still agree.
3. **Adapter defect** (the harness misreads the engine): write the failing adapter test in
   `test_adapter.py` first, fix, rerun.

An operator or transformation the library does not register (load error "Operator … not
found" / "transformation … not found") on a feature that `spec/06`/`07` marks Extended or
Deprecated goes into `UNSUPPORTED_*`; on a Core feature it is a known-gaps row.

Obsolete-row failures: delete the row (the prediction was wrong) and note it in the
commit message.

Repeat the run until the only remaining failures are none: `grep -c "^FAIL\|^ERROR" $SCRATCH/v3runN.txt` → `0`.

- [ ] **Step 4: Update prose in `compat/known-gaps.md` and the Coraza README**

In `compat/known-gaps.md` intro replace the two sentences starting "Rows naming Coraza are **verified**" with:

```
Rows naming Coraza or libmodsecurity v3 are **verified**: `adapters/coraza` and
`adapters/libmodsecurity` run every test in CI and fail when a listed file passes or an
unlisted one fails. Rows naming only ModSecurity v2 remain predictions from source until
an adapter exists for it.
```

In `adapters/coraza/README.md`, section "Adding another engine", append:

```
`adapters/libmodsecurity` is the second reference adapter (Python, ctypes over the C API);
it reuses nothing from this module but follows the same gating.
```

- [ ] **Step 5: Write `adapters/libmodsecurity/README.md`**

```markdown
# libmodsecurity v3 reference adapter

Runs the conformance data in `../../tests` against
[libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity) v3 through its C API,
with `ctypes`, as `unittest`.

```sh
export MODSECURITY_LIB=/path/to/libmodsecurity.so   # or .dylib
uv run python -m unittest discover -s adapters/libmodsecurity                  # everything
uv run python -m unittest discover -s adapters/libmodsecurity -p test_conformance.py -v
uv run python -m unittest discover -s adapters/libmodsecurity -p test_adapter.py   # adapter self-tests
```

Without `MODSECURITY_LIB` the conformance tests and the engine smoke tests are skipped.

## Building the library

CI builds v3.0.16 from source (`.github/workflows/validate.yml`, job
`libmodsecurity-adapter`) and caches the install. The same recipe works locally; the
build needs libxml2, yajl and PCRE2 development packages so that XML and JSON bodies and
the regex operators are available:

```sh
git clone --depth 1 -b v3.0.16 --recurse-submodules --shallow-submodules https://github.com/owasp-modsecurity/ModSecurity.git
cd ModSecurity && ./build.sh
./configure --prefix=$HOME/modsecurity --disable-doxygen-doc --disable-examples \
  --without-lua --without-lmdb --without-ssdeep --without-curl --without-geoip --without-maxmind
make -j$(nproc) && make install
export MODSECURITY_LIB=$HOME/modsecurity/lib/libmodsecurity.so
```

On macOS with Homebrew add `--with-pcre2=/opt/homebrew/opt/pcre2
--with-libxml=/opt/homebrew/opt/libxml2 --with-yajl=/opt/homebrew/opt/yajl`.

## How results are gated

`compat/known-gaps.md` is the expected-failure list; rows whose Engine cell names
`libmodsecurity v3` apply. For each test file:

| Row for this engine | Result | Outcome |
|---|---|---|
| none | all pass | pass |
| none | any failure | **fail** (a real defect in the engine or in the specification) |
| present | any failure | pass, failures printed as `expected (known gap: …)` |
| present | all pass | **fail** with `known-gaps row is obsolete` (remove the row) |

Extended features the library does not implement are skipped, not failed: profiles
through `requires:`, unit files through the `UNSUPPORTED_*` sets in `test_conformance.py`.

## How the tiers are driven

- **Engine tier** (`engine_tier.py`): the profile's `files:` and its rules are written
  under a temporary directory and loaded with `msc_rules_add_file`, so relative `Include`
  paths resolve. `SecDebugLog`/`SecDebugLogLevel 4` are appended because the C API has no
  "matched rules" call that includes `nolog` rules; the debug log segment written during
  the stage is parsed for `(Rule: N)`, `Rule returned 0|1.`, `Executing unconditional
  rule` and `Running (disruptive) action:` lines. `interruption` combines that with
  `msc_intervention` (status, URL). `log_contains` searches the error-log callback lines
  plus the intervention's own log line (v3 routes a denying rule's message there).
- **Unit tier** (`unit_tier.py`): each case is a rule over `REQUEST_BODY` carrying `log`;
  the input is sent as raw bytes (unit strings are Latin-1 byte strings). Transformation
  output is read from the error log through `t:hexEncode,msg:'%{MATCHED_VAR}'`, which is
  binary safe and untruncated; `re_groups` through one `TX:i` rule per group. Parameters
  are inserted verbatim: v3 keeps `\\` pairs and treats `\"` as two characters, and no
  unit parameter contains `"`.

## Known limits

- An engine crash cannot be caught from `ctypes` and aborts the run.
- The debug-log line formats are those of v3.0.16; a release that changes them needs
  `engine_tier.parse_debug_log` updated (its tests in `test_adapter.py` pin the formats).
```

- [ ] **Step 6: Full verification**

Run: `MODSECURITY_LIB=$SCRATCH/msc/install/lib/libmodsecurity.dylib uv run python -m unittest discover -s adapters/libmodsecurity 2>&1 | tail -3 && uv run python tools/validate.py && uv run python -m unittest discover -s tools -t . 2>&1 | tail -1 && (cd adapters/coraza && go test ./... 2>&1 | tail -1)`
Expected: `OK` for the adapter; validator `OK`; tools suite `OK`; Coraza `ok`.

- [ ] **Step 7: Commit**

```bash
git add adapters/libmodsecurity compat/known-gaps.md adapters/coraza/README.md spec tests
git commit -m "feat(libmodsecurity): conformance runner, first-run triage, README"
```

---

### Task 6: CI job, ADR-0023, root README

**Files:**
- Modify: `.github/workflows/validate.yml`, `adr/0023-reference-adapters.md`, `README.md`

- [ ] **Step 1: Add the CI job**

Append to `.github/workflows/validate.yml`:

```yaml
  libmodsecurity-adapter:
    runs-on: ubuntu-latest
    env:
      MSC_VERSION: v3.0.16
      MSC_PREFIX: /home/runner/modsecurity
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y libpcre2-dev libxml2-dev libyajl-dev
      - uses: actions/cache@v4
        id: msc
        with:
          path: /home/runner/modsecurity
          key: libmodsecurity-${{ env.MSC_VERSION }}-${{ runner.os }}-${{ runner.arch }}
      - if: steps.msc.outputs.cache-hit != 'true'
        run: |
          sudo apt-get install -y automake libtool pkg-config g++ make
          git clone --depth 1 -b "$MSC_VERSION" --recurse-submodules --shallow-submodules https://github.com/owasp-modsecurity/ModSecurity.git /tmp/msc
          cd /tmp/msc && ./build.sh
          ./configure --prefix="$MSC_PREFIX" --disable-doxygen-doc --disable-examples \
            --without-lua --without-lmdb --without-ssdeep --without-curl --without-geoip --without-maxmind
          make -j"$(nproc)" && make install
      - uses: astral-sh/setup-uv@v6
        with:
          python-version: "3.12"
      - run: uv sync
      - run: uv run python -m unittest discover -s adapters/libmodsecurity -v
        env:
          MODSECURITY_LIB: /home/runner/modsecurity/lib/libmodsecurity.so
```

- [ ] **Step 2: Validate the workflow file parses**

Run: `uv run python -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/validate.yml')); print(sorted(d['jobs']))"`
Expected: `['coraza-adapter', 'libmodsecurity-adapter', 'validate']`

- [ ] **Step 3: Update ADR-0023**

In `adr/0023-reference-adapters.md`:
- Decision, last sentence → `The reference adapters are \`adapters/coraza\` (Go, Coraza v3.8.1 pinned) and \`adapters/libmodsecurity\` (Python over the C API, libmodsecurity v3.0.16 built by CI).`
- Consequences: replace the bullet "Known-gaps rows for Coraza are now verified; rows for the ModSecurity branches remain predictions until an adapter exists for them." with `Known-gaps rows for Coraza and libmodsecurity v3 are verified; rows for ModSecurity v2 remain predictions until an adapter exists for it.` and add `- CI builds libmodsecurity from source (cached by tag); the libmodsecurity adapter reads matched rules from the engine debug log because the C API omits \`nolog\` matches.`
- Tests: add `- \`adapters/libmodsecurity/test_conformance.py\` (\`TestEngine\`, \`TestUnit\`)`
- References: add `adapters/libmodsecurity/README.md`.

- [ ] **Step 4: Root README**

Find the paragraph that mentions `adapters/coraza` in `README.md` (`grep -n adapters README.md`) and add one sentence after it: `A second adapter, \`adapters/libmodsecurity\`, runs the same data against libmodsecurity v3.0.16 through its C API (Python, \`MODSECURITY_LIB\`).` If the README has no such paragraph, add a short "Reference adapters" section listing both.

- [ ] **Step 5: Validator and commit**

Run: `uv run python tools/validate.py && uv run python -m unittest discover -s tools -t . 2>&1 | tail -1`
Expected: `OK` twice.

```bash
git add .github/workflows/validate.yml adr/0023-reference-adapters.md README.md
git commit -m "feat(libmodsecurity): CI job building v3.0.16 from source; ADR-0023 names both adapters"
```
