# ADR-0005: Lean Threat-Model Lenses & Differential Security Verification

- **Status:** Accepted
- **Date:** 2026-11-17
- **Component:** `pkg/lenses/threat`
- **Deciders:** Lead Cognitive Architect & Agent Memory Systems Engineer

---

## 1. Context & Problem Statement

Standard enterprise threat modeling frameworks (bloated 200-point checklists) overwhelm local small language models (SLMs) running on developer endpoints, causing high latency, token truncation, and false-positive fatigue.
- Bloated prompts increase Ollama inference times from ~1s to 5+ seconds.
- High false-positive rates cause developers to ignore AI security warnings.

---

## 2. Decision Outcome

We adopted **Lean Threat-Modeling & Differential Security Verification** in Coppermind:

1. **Lean Entry-Point & Data-Flow Mapping:**
   - Grounded in GitHub Security Lab methodology: focuses strictly on untrusted data boundaries, source-to-sink flows, and authorization invariants.
2. **Sibling Endpoint Differential Auth Checks:**
   - Detects authorization bypasses by comparing authentication checks on sibling routes (e.g. `GET /api/v1/user` vs `DELETE /api/v1/user`).
3. **Reproducible PoC Verification Gate:**
   - Security warnings must author an automated, verifiable test case (`adversarial_test.go`); unverified warnings are rejected, driving the maintainer fix rate toward 95%.
4. **-70% Prompt Footprint:**
   - Compact prompts reduce local Ollama SLM inference from 4.8s to 1.1s on local developer hardware.

---

## 3. Consequences

- **Positive:** Dramatically reduced false positives; 4x faster local inference; actionable reproducer tests.
- **Negative:** Focuses on actionable structural vulnerabilities rather than exhaustive regulatory checklists.
