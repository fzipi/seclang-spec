"""Assemble an OWASP CRS checkout into one engine profile the Lean model can carry.

Usage: uv run python tools/crs_profile.py /path/to/coreruleset > formal/.lake/crs-profile.yaml
Then: (cd adapters/coraza && go run ./cmd/differential -profile ../../formal/.lake/crs-profile.yaml -n 20 -seed 1 > ../../formal/.lake/crs-diff.json)
      (cd formal && lake exe seclang-eval .lake/crs-diff.json)

The profile is crs-setup.conf.example and every rules/*.conf, prefixed with the engine
directives a deployment's modsecurity.conf supplies, minus the rule blocks the model does
not carry (libinjection, XML, file inspection, persistent collections, body limits) and
minus the update/remove directives that name a dropped rule; `XML:` targets are stripped
from mixed variable lists. The .data files are the profile's files. A chain member without
an action list keeps a blank line after it, which libmodsecurity's parser needs.
"""
import re
import sys
from pathlib import Path

ENGINE = ("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n"
          "SecResponseBodyMimeType text/plain text/html text/xml\nSecRequestBodyJsonDepthLimit 512\n")
DROP = re.compile(r"@detectSQLi|@detectXSS|@inspectFile|@geoLookup|@rbl|@validateDTD|@validateSchema|@fuzzyHash"
                  r"|requestBodyProcessor=XML|\bXML\b(?!:)|@validateByteRange|SecRemoteRules|initcol|expirevar"
                  r"|setsid|setuid|setrsc|\bIP[:.]|\bGLOBAL[:.]|REQBODY_ERROR|SecRequestBodyLimit|SecResponseBodyLimit", re.I)
UPDATE = re.compile(r"\s*SecRule(?:UpdateTargetById|UpdateActionById|RemoveById)\s+(\S+)")


def blocks(text: str) -> list[str]:
    """Logical directives: continuation lines joined, comments and blank lines dropped."""
    cur, out = [], []
    for line in text.splitlines():
        if cur:
            cur.append(line)
            if not line.rstrip().endswith("\\"):
                out.append("\n".join(cur))
                cur = []
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.rstrip().endswith("\\"):
            cur = [line]
        else:
            out.append(line)
    if cur:
        out.append("\n".join(cur))
    return out


def chains(bs: list[str]) -> list[list[str]]:
    """Group a chain starter with its members (a member carries no `chain` of its own)."""
    groups, i = [], 0
    while i < len(bs):
        group = [bs[i]]
        while re.search(r"\bchain\b", group[-1]) and i + 1 < len(bs):
            i += 1
            group.append(bs[i])
        i += 1
        groups.append(group)
    return groups


def assemble(crs: Path) -> tuple[str, int]:
    """The profile YAML and the number of directives dropped."""
    confs = [crs / "crs-setup.conf.example"] + sorted((crs / "rules").glob("*.conf"))
    kept, dropped, dropped_ids = [], 0, set()
    for c in confs:
        for group in chains(blocks(c.read_text(encoding="utf-8"))):
            text = "\n".join(group)
            if DROP.search(text):
                dropped += len(group)
                dropped_ids.update(re.findall(r"\bid:(\d+)", text))
                continue
            text = re.sub(r"XML:[^|\s\"]*\|", "", text)
            text = re.sub(r"\|XML:[^|\s\"]*", "", text)
            kept.append(text)

    def names_dropped(b: str) -> bool:
        m = UPDATE.match(b)
        return bool(m) and any(i in dropped_ids for i in re.findall(r"\d+", m.group(1)))

    kept = [b for b in kept if not names_dropped(b)]
    files = {p.name: p.read_text(encoding="utf-8") for p in sorted((crs / "rules").glob("*.data"))}
    rules = ENGINE + "\n\n".join(kept) + "\n"
    yaml = ("meta:\n  name: crs\n  description: OWASP CRS, minus the rules the model does not carry\n"
            "spec: 03-processing-model.md#phases\n")
    yaml += "files:\n" + "".join(f"  {n}: |\n" + "".join("    " + l + "\n" for l in t.splitlines()) for n, t in files.items())
    yaml += "rules: |\n" + "".join("  " + l + "\n" for l in rules.splitlines()) + "tests: []\n"
    return yaml, dropped


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: crs_profile.py CRS_DIR")
    text, dropped = assemble(Path(sys.argv[1]))
    sys.stdout.write(text)
    print(f"{dropped} directives dropped", file=sys.stderr)
