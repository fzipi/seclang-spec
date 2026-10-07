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
