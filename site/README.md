# Specification website

Hugo site that publishes `spec/`, `compat/` and `adr/` straight from the repository
markdown. Nothing under `site/content` duplicates a source file: content adapters
(`content/*/_content.gotmpl`) turn each mounted markdown file into a page, taking the title
from its first heading and the order from its numeric prefix, and rewriting the
repository's backticked references (`06-operators.md#rx`, `tests/...`, `ADR-0024`) into
links.

```sh
cd site
hugo server          # preview at http://localhost:1313/seclang-spec/
hugo --gc --minify --cleanDestinationDir   # build into site/public
./smoke.sh           # assert the expected pages, titles and links exist
```

Requirements: Hugo extended ≥ 0.146 and Go (the Hextra theme is a Hugo module, pinned in
`go.mod`). `.github/workflows/pages.yml` builds the site on every pull request and deploys
it to GitHub Pages on pushes to `main`; Pages must be enabled once in the repository
settings with "GitHub Actions" as the source.
