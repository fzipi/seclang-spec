---
title: SecLang Specification
layout: hextra-home
---

{{< hextra/hero-headline >}}
SecLang Specification
{{< /hextra/hero-headline >}}

{{< hextra/hero-subtitle >}}
A formal specification for the ModSecurity rule language, with engine-neutral conformance
tests, a verified compatibility matrix and the decisions behind every divergence.
{{< /hextra/hero-subtitle >}}

{{< cards >}}
  {{< card link="spec" title="Specification" subtitle="Grammar, processing model, directives, variables, operators, transformations, actions, body processors and logging." icon="book-open" >}}
  {{< card link="compat/known-gaps" title="Known gaps" subtitle="Core tests each surveyed engine fails today, verified in CI by the reference adapters." icon="table" >}}
  {{< card link="compat/matrix" title="Engine matrix" subtitle="Every feature across ModSecurity v2, libmodsecurity v3 and Coraza, with its specification status." icon="view-grid" >}}
  {{< card link="formal/results" title="Formal model" subtitle="Lean 4 model run against the corpus, every engine profile and OWASP CRS, with theorems for the decisions." icon="beaker" >}}
  {{< card link="adr" title="Decisions" subtitle="Architecture Decision Records for the choices made where engines diverge." icon="scale" >}}
  {{< card link="tests" title="Conformance tests" subtitle="The test data contract, and how each reference adapter drives its engine and gates the results." icon="clipboard-check" >}}
{{< /cards >}}
