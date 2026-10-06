# 01. Lexical structure

SecLang configuration is line-oriented text. This file defines how lines become
directives; `02-grammar.md` defines what a directive line may contain.

### Lines and directives

**Status:** Core

**Syntax.** A configuration file is a sequence of lines separated by LF or CRLF. After
line continuation (below) each logical line is empty, a comment, or one directive. A
directive is a name followed by zero or more whitespace-separated arguments.

**Semantics.** Engines MUST accept both LF and CRLF line endings. Leading and trailing
whitespace on a line is ignored. Empty lines are ignored. The character encoding of a
configuration file is bytes; engines MUST NOT reject non-ASCII bytes inside quoted
arguments (operator parameters routinely contain them).

**Divergence notes.** None known.

**Tests.** `tests/engine/lexical/crlf-line-endings.yaml`

### Comments

**Status:** Core

**Syntax.** A logical line whose first non-blank character is `#` is a comment.

**Semantics.** Comment lines are discarded before any directive is parsed. There are no
trailing comments: a `#` anywhere after the first non-blank character is data and
reaches the directive unchanged. Because line continuation is applied first, a comment
line ending in `\` continues onto the next physical line and the whole logical line is
the comment; engines MUST NOT parse the continued text as a directive (ADR-0013).

**Divergence notes.** ModSecurity v2 (Apache joins continuation lines before testing
for `#`) and libmodsecurity v3 (`src/parser/seclang-scanner.ll` enters a comment state
on `# SecRule … \`) behave as specified. Coraza 3.8.1 drops the comment line before
testing for a trailing backslash (`internal/seclang/parser.go`, the `#` check precedes
the continuation check), so the continued text is parsed as a new directive. A
commented-out multi-line rule therefore comes back to life in Coraza. See ADR-0013.

**Tests.** `tests/engine/lexical/comment-lines.yaml`,
`tests/engine/lexical/comment-with-trailing-backslash.yaml`

### Line continuation

**Status:** Core

**Syntax.** A physical line whose last non-blank character is `\` continues onto the
next physical line.

**Semantics.** The backslash and the line break are removed and the two pieces are
joined with no inserted character. Whitespace before the backslash and leading
whitespace on the continuation line are kept as written; rule authors rely on this to
indent continued lines inside a quoted action list. Continuation may repeat over any
number of lines. OWASP CRS v4 contains over seven thousand continued lines, so this is
the most exercised lexical feature in practice.

**Divergence notes.** None known for directive lines. For comment lines see
`#comments` and ADR-0013.

**Tests.** `tests/engine/lexical/continuation-lines.yaml`

### Quoting and escapes

**Status:** Core

**Syntax.** A directive argument is either a bare token, which extends to the next
whitespace, or a string delimited by double quotes `"`. Inside double quotes, `\"` is a
literal double quote and `\\` is a literal backslash; any other backslash sequence is
passed through unchanged to the directive, which may interpret it (regular expressions
do, for example).

**Semantics.** The quotes are delimiters, not part of the argument. An argument that
contains whitespace, `"` or begins with `@` or `!` SHOULD be quoted. Single quotes are
not argument delimiters at this level; they delimit values *inside* an action list and
are defined in `02-grammar.md#action-list`.

**Divergence notes.** None known. Engines differ in how they parse `\"` inside the
action list after macro expansion; a libmodsecurity v3 fix for an escaped quote
following a macro landed in 2026 and that case is tested in `02-grammar.md`.

**Tests.** `tests/engine/lexical/quoted-arguments.yaml`

### Include

**Status:** Core

**Syntax.** `Include PATH`

**Semantics.** The file at `PATH` is parsed in place, as if its lines replaced the
`Include` line. If `PATH` contains `*`, it is a glob pattern; every matching file is
included in lexicographic order. Engines MUST support absolute paths and `*` globs. A
non-glob `PATH` that does not exist MUST be a configuration error. A glob that matches
nothing MUST NOT be an error (engines MAY warn). Included files may themselves
`Include`; an engine MAY cap the total number of included files, and the cap MUST be at
least 100.

The directory against which a *relative* `PATH` is resolved is **not specified**: see
the divergence note. Portable configurations use absolute paths or paths relative to a
directory the deployment controls.

**Divergence notes.** ModSecurity v2 uses the Apache `Include` directive, which resolves
relative paths against `ServerRoot`. libmodsecurity v3 and Coraza resolve them against
the directory of the including file (Coraza: `internal/seclang/parser.go`, which also
caps includes at 100 files via `maxIncludeRecursion`). Coraza only treats `PATH` as a
glob when it contains `*`; Apache also expands `?` and `[...]`. Only `*` is Core.

**Tests.** `tests/engine/lexical/include-relative-file.yaml`

### Name matching

**Status:** Core

**Syntax.** Directive names (`SecRule`), operator names (`@contains`), action names
(`deny`, `t:`), transformation names (`lowercase`) and `ctl:` option names
(`ruleEngine`) are identifiers made of ASCII letters and digits.

**Semantics.** Engines MUST match all of these identifiers case-insensitively.
`secrule`, `SecRule` and `SECRULE` denote the same directive; `@CONTAINS` and
`@contains` the same operator; `T:LOWERCASE` and `t:lowercase` the same
transformation. The canonical spelling used in this specification is the mixed-case
form from the ModSecurity reference manual; engines SHOULD emit that spelling in logs
and error messages.

Variable and collection names (`ARGS`, `TX`) and collection keys are **not** covered by
this section; their case rules are defined with the variables (ADR-0008, Phase 3).

**Divergence notes.** ModSecurity v2 and v3 already behave this way. Coraza 3.8.1
matches directive, action and transformation names case-insensitively but operator
names case-sensitively. See ADR-0002.

**Tests.** `tests/engine/lexical/case-insensitive-names.yaml`
