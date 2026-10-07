# Specification Website — Design

Status: approved in conversation, 2026-10-07.

## 1. Brief

**You said.** Generate a webpage that shows the known gaps in a table, preferably with Hugo
and a reasonable theme. Full spec site; hosted on GitHub Pages via Actions.

**Agreed.** A Hugo site under `site/` that publishes the specification chapters, the
compatibility pages (known gaps, engine matrix) and the ADRs straight from the repository
markdown, with the Hextra theme, built on every pull request and deployed to GitHub Pages
on pushes to `main`.

**Assumptions.**

- The repository markdown stays the single source: nothing is copied into `site/content`.
- Hugo extended ≥ 0.146 (content adapters, `useEmbedded` link hooks); 0.166.0 pinned in CI.
- Hextra is pulled as a Hugo module (needs Go at build time; Go is already in CI for the
  Coraza adapter).
- The repository owner enables Pages once (Source: GitHub Actions).

## 2. Shape

```
site/
  hugo.yaml                 baseURL, theme import, mounts (../spec, ../compat, ../adr -> assets/src/*),
                            markup (useEmbedded link hook, TOC levels), Hextra params
  go.mod, go.sum            Hugo module pin: github.com/imfing/hextra v0.13.0
  content/_index.md         landing page (layout: hextra-home) with three cards
  content/spec/_index.md    section title "Specification", weight 1
  content/spec/_content.gotmpl   adapter: one page per ../spec/*.md
  content/compat/_index.md  section title "Compatibility", weight 2
  content/compat/_content.gotmpl adapter: known-gaps and matrix pages
  content/adr/_content.gotmpl    adapter: README.md -> section index, 0000-template skipped
  README.md                 how to build and preview
.github/workflows/pages.yml  build on pull_request; build + deploy on push to main
```

`site/public` and `site/resources` are git-ignored.

## 3. Content adapters

Each adapter ranges over `resources.Match "src/<dir>/*.md"` and calls `AddPage` with:

- `path`: the file stem (`README` becomes `_index`);
- `title`: the first `# ` heading, falling back to the stem;
- `weight`: the leading digits of the stem with leading zeros stripped (999 when none), so
  chapters and ADRs sort numerically;
- `content`: the markdown with the first heading removed (the theme renders the title),
  media type `text/markdown`.

`0000-template.md` is skipped. Relative links such as `06-operators.md#rx` and
`0023-reference-adapters.md` are resolved by Hugo's embedded link render hook
(`markup.goldmark.renderHooks.link.useEmbedded: fallback`), which maps `x.md` to the page
`x` in the same section; anchors are kept.

## 4. Build and deploy

`cd site && hugo` builds; `hugo server` previews. The workflow:

- `on: pull_request` and `push: branches: [main]`;
- job `build`: checkout, `actions/setup-go`, `peaceiris/actions-hugo@v3` (0.166.0,
  extended), `actions/configure-pages` (on main only, for the base URL), `hugo --gc
  --minify -s site --baseURL <pages url>/`, `actions/upload-pages-artifact` with
  `site/public`;
- job `deploy` (main only): `actions/deploy-pages@v4`, environment `github-pages`,
  permissions `pages: write`, `id-token: write`; the workflow default is `contents: read`.

## 5. Errors and limits

- A broken `.md` link is not a build error (Hugo renders it unresolved); the PR build only
  catches template errors. Acceptable for now; a link check is a later addition.
- Adapter pages have no source file, so Hextra's edit-this-page link is disabled.
- Search is Hextra's built-in FlexSearch index, generated at build time.

## 6. Testing

The build itself is the test: `hugo` must exit 0, and a smoke script in the plan checks
that the expected pages exist, titles come from headings, no `href="…​.md…"` survives in
`site/public`, and the known-gaps page contains a table.
