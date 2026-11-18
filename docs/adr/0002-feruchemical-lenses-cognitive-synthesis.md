# ADR-0002: Feruchemical Lenses & Cognitive Memory Synthesis

- **Status:** Accepted
- **Date:** 2026-11-15
- **Component:** `pkg/lenses`, `pkg/worker`
- **Deciders:** Lead Cognitive Architect & Agent Memory Systems Engineer

---

## 1. Context & Problem Statement

Raw conversational transcripts and raw git commits contain noise that quickly saturates LLM context windows.
- Storing un-distilled transcripts leads to context exhaustion and high inference costs.
- Different agent tasks require different analytical perspectives (e.g. security threat modeling vs. performance optimization vs. architectural compliance).

---

## 2. Decision Outcome

We introduced **Feruchemical Lenses**: asynchronous, specialized analytical personas that distill raw experience into structured cognitive memories:

1. **Pluggable Analytical Lenses:**
   - Security Lens (STRIDE & fail-closed verification).
   - Systems Architect Lens (Hop Tax & $N=8$ multi-agent concurrency).
   - Synthesizer Lens (Cross-project pattern reuse).
   - Devil's Advocate Lens (Assumption stress-testing).
2. **Asynchronous Reflection Workers:**
   - Background worker processes analyze completed sessions outside the interactive request loop (0ms hop tax on developer turns).
3. **Quarantined Observations:**
   - Distilled insights are stored in an `observations` table marked `derived: true`, isolated from canonical source facts.

---

## 3. Consequences

- **Positive:** Reduces token consumption by up to 80%; provides curated, high-density context tailored to the task persona.
- **Negative:** Requires background LLM inference (via local Ollama or cloud router) during idle windows.
