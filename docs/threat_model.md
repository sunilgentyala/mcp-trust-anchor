# Threat Model: MCP Cross-Boundary Context Poisoning

**Repository:** github.com/sunilgentyala/mcp-trust-anchor
**Author:** Sunil Gentyala, HCLTech

---

## System Description

An agentic AI stack where multiple AI agents invoke tools via the Model Context Protocol (MCP). Agents operate at different trust levels. Some agents read from low-trust external sources (public web, third-party APIs). Others operate with access to high-trust internal systems (code execution, internal databases, privileged APIs).

---

## Trust Boundaries

| Zone | Examples | Trust Level |
|---|---|---|
| External | Public websites, RSS feeds, unauthenticated APIs | PUBLIC |
| Internal | Authenticated microservices, internal APIs | INTERNAL |
| Restricted | PII stores, regulated databases | CONFIDENTIAL |
| Classified | HSM-gated sources, air-gapped systems | RESTRICTED |

---

## Primary Threat: Cross-Boundary Context Poisoning

**Threat ID:** MCP-T-001
**MITRE ATLAS mapping:** AML.T0051 (LLM Prompt Injection), AML.T0054 (Indirect Prompt Injection)
**CVSS base score (estimated):** 8.1 (High) — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N

### Attack Narrative

1. An attacker embeds adversarial instructions in a public-facing resource (webpage, API response, document).
2. Agent A, scoped to read external content, fetches the resource via an MCP tool call.
3. Agent A packages the fetched content as an MCP context payload and passes it to Agent B.
4. Agent B, operating with internal credentials, processes the payload without provenance verification.
5. The adversarial instructions execute with Agent B's trust level.

### Impact

- Indirect privilege escalation: attacker achieves high-trust execution without direct system access.
- Data exfiltration: adversarial instructions redirect Agent B's API calls to attacker-controlled endpoints.
- Lateral movement: compromised Agent B context can propagate further into downstream tool chains.

### Root Cause

MCP context payloads carry no native provenance metadata. The protocol does not distinguish a payload sourced from a vetted internal system from one sourced from an attacker-controlled public page.

---

## Secondary Threats

**MCP-T-002: Payload Tampering in Transit**
An adversary intercepts an MCP context envelope between agents and modifies the payload content before it reaches the high-trust tool.
Mitigation: SHA-256 payload digest embedded in the signed JWT. Any modification invalidates the digest check.

**MCP-T-003: Agent Identity Spoofing**
An adversary generates their own key pair, claims a legitimate agent identity in the `iss` JWT claim, and attempts to pass a RESTRICTED trust level.
Mitigation: Signature verification against the registered public key registry. An unknown key produces a signature that fails ECDSA verification.

**MCP-T-004: Replay Attack**
An adversary captures a valid signed envelope and replays it after the original context is no longer valid.
Partial mitigation: JWT expiry (TTL). Full mitigation requires a nonce registry (not implemented in this PoC).

**MCP-T-005: Trust Level Inflation**
An agent registered with max_trust_level=PUBLIC attempts to sign an envelope claiming CONFIDENTIAL.
Mitigation: key_registry.py stores per-agent max_trust_level. The validator can enforce this in addition to the tool's minimum threshold. Not enforced by default in this PoC.

---

## Controls Summary

| Threat | Control | Implemented in PoC |
|---|---|---|
| Cross-boundary poisoning (MCP-T-001) | Trust level gating in mcp_validator.py | Yes |
| Payload tampering (MCP-T-002) | SHA-256 digest in signed JWT | Yes |
| Agent identity spoofing (MCP-T-003) | ECDSA P-256 signature verification | Yes |
| Replay attacks (MCP-T-004) | JWT TTL (300s default) | Partial |
| Trust level inflation (MCP-T-005) | Per-agent max_trust_level in registry | Stub only |

---

## Out of Scope for This PoC

- Prompt injection at the model inference layer (pre-MCP)
- Compromised agent runtime environments
- Side-channel attacks on ECDSA key material
- Denial of service against the validation gate
