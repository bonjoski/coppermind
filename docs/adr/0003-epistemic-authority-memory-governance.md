# ADR-0003: Epistemic Authority & Role-Based Memory Governance

- **Status:** Accepted
- **Date:** 2026-11-15
- **Component:** `pkg/security`, `pkg/db/postgres`
- **Deciders:** Lead Cognitive Architect & Agent Memory Systems Engineer

---

## 1. Context & Problem Statement

In autonomous multi-agent swarms, agents of varying authority and trustworthiness generate conflicting memories.
- An untrusted junior subagent or tainted external web search could overwrite a foundational architectural constraint.
- Without strict epistemic ranking, memory databases suffer from hallucinations, cognitive drift, and memory poisoning attacks (OWASP LLM01).

---

## 2. Decision Outcome

We established an **Epistemic Authority Hierarchy** governing Coppermind memories:

1. **Epistemic Tiers:**
   - **Tier 0 (Immutable Canonical Truth):** Git commit history, signed release tags, source code AST.
   - **Tier 1 (Authoritative Directives):** Human-authored ADRs, repository `AGENTS.md` instructions, signed policy manifests.
   - **Tier 2 (Verified Cognitive Observations):** Insights validated by deterministic test suites or compiler passes.
   - **Tier 3 (Hypotheses & Inferences):** Unverified LLM reflections, probabilistic scratchpad thoughts.
2. **Monotonic Authority Invariant:**
   - A memory node of lower epistemic authority can **never** overwrite, mutate, or supersede a node of higher epistemic authority.
   - Any conflicting write from a lower-tier agent is automatically downgraded to a quarantined proposal.

---

## 3. Consequences

- **Positive:** Mathematically prevents memory poisoning and cognitive drift; guarantees that human ADRs remain authoritative.
- **Negative:** Conflicting updates from subagents must be explicitly reconciled or reviewed.
