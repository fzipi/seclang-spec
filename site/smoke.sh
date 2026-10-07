#!/bin/sh
# Run after `hugo -s site`; exits non-zero on the first missing property of the built site.
# The minifier drops attribute quotes, so hrefs are matched with an optional quote.
set -eu
P="$(cd "$(dirname "$0")" && pwd)/public"
check() { name=$1; shift; if "$@" >/dev/null 2>&1; then echo "ok   $name"; else echo "FAIL $name"; exit 1; fi; }
check pages        test -f "$P/spec/06-operators/index.html" -a -f "$P/compat/known-gaps/index.html" -a -f "$P/compat/matrix/index.html" -a -f "$P/adr/0024-ipmatch-invalid-entries/index.html" -a -f "$P/adr/index.html"
check title        grep -q '<title>06. Operators' "$P/spec/06-operators/index.html"
check anchor       grep -qE 'href="?[^" >]*/spec/03-processing-model/#chains' "$P/spec/08-actions/index.html"
check adr-index    grep -qE 'href="?[^" >]*/adr/0023-reference-adapters/' "$P/adr/index.html"
check adr-ref      grep -qE 'href="?[^" >]*/adr/0002-case-insensitive-names/' "$P/compat/known-gaps/index.html"
check test-ref     grep -qE 'href="?https://github.com/fzipi/seclang-spec/blob/main/tests/engine/actions/setvar.yaml' "$P/compat/known-gaps/index.html"
check template     test ! -e "$P/adr/0000-template"
check gaps-table   grep -q '<th>Behaviour today</th>' "$P/compat/known-gaps/index.html"
check no-md-links  sh -c "! grep -rqoE 'href=\"?/[^\" >]*\.md' '$P/spec' '$P/adr' '$P/compat'"
echo "smoke: all checks passed"
