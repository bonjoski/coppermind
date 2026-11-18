# ADR-0004: Extensible Industry Radar & Threat Intel Ingestion

- **Status:** Accepted
- **Date:** 2026-11-16
- **Component:** `pkg/radar`, `pkg/capsule`
- **Deciders:** Lead Cognitive Architect & Agent Memory Systems Engineer

---

## 1. Context & Problem Statement

AI coding agents have knowledge cutoff dates and are unaware of recent critical security vulnerabilities, zero-day CVE advisories, and framework deprecations.
- Hand-editing prompt context windows with latest CVE lists is brittle and labor-intensive.
- External web lookups during agent execution add latency (1000ms+) and risk SSRF or prompt injection from untrusted web content.

---

## 2. Decision Outcome

We built the **Extensible Industry Radar Subsystem** in Coppermind:

1. **Declarative `radar.yaml` Ecosystem Packs:**
   - Pre-curated, language-specific threat intelligence packs (Go/Rust, JVM, Node/TS, Python, Cloud Security).
2. **Out-of-Band Asynchronous Ingestion:**
   - Feeds are synced and embedded in the background outside interactive agent turns (0ms hop tax).
3. **Cognitive Firewall Quarantine:**
   - Raw threat intel feeds are sanitized via Stormcage cognitive firewalls to strip embedded prompt injections before vector indexing.
4. **Air-Gapped Capsule Export:**
   - Allows exporting immutable, signed `.capsule` archives for distribution to air-gapped workstations.

---

## 3. Consequences

- **Positive:** Agents ground security reviews against latest CVE benchmarks without runtime internet latency.
- **Negative:** Requires periodic background synchronization of radar feeds.
