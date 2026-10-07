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
