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
  {{< card link="spec" title="Specification" subtitle="Lexical structure, grammar, processing model, directives, variables, operators, transformations, actions, body processors and logging." icon="book-open" >}}
  {{< card link="compat/known-gaps" title="Known gaps" subtitle="Core tests each surveyed engine fails today, verified in CI by the reference adapters." icon="table" >}}
  {{< card link="compat/matrix" title="Engine matrix" subtitle="Every directive, variable, operator, transformation and action across ModSecurity v2, libmodsecurity v3 and Coraza." icon="view-grid" >}}
  {{< card link="adr" title="Decisions" subtitle="Architecture Decision Records for the choices made where engines diverge." icon="scale" >}}
{{< /cards >}}
