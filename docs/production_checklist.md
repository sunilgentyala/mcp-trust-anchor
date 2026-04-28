# Production Checklist

**Repository:** github.com/sunilgentyala/mcp-trust-anchor
**Author:** Sunil Gentyala, HCLTech

This checklist covers the controls deliberately omitted from the PoC.
Complete all items before deploying the context-signing framework in a
production agentic workload.

---

## Key Management

- [ ] Store all private keys in an HSM or secrets manager (AWS KMS, Azure Key Vault, HashiCorp Vault). Never write private key material to disk in plaintext.
- [ ] Enforce a maximum key lifetime of 90 days. Automate rotation.
- [ ] Implement key revocation. A compromised agent key must be removable from the registry without restarting other agents.
- [ ] Use separate key pairs per agent, per environment (dev, staging, prod). Never share keys across environments.
- [ ] Log all key generation, rotation, and revocation events to an immutable audit trail.

---

## Distributed Key Registry

- [ ] Replace the in-memory KeyRegistry stub with a centralized PKI-backed registry (e.g. SPIFFE/SPIRE, internal CA, or a secrets manager with access controls).
- [ ] Implement registry polling or push-based updates so validators pick up rotated keys within a defined SLA (recommended: 5 minutes maximum lag).
- [ ] Enforce TLS on all registry reads. Treat registry endpoints as high-trust internal services.
- [ ] Apply rate limiting and authentication to registry write operations. Only designated key management services should register new agents.

---

## Replay Attack Prevention

- [ ] Maintain a nonce registry (Redis or a fast key-value store) that tracks used `jti` (JWT ID) values.
- [ ] Reject any envelope whose `jti` appears in the nonce registry, regardless of signature validity.
- [ ] Expire nonce registry entries after 2x the maximum envelope TTL to bound storage growth.
- [ ] Tune envelope TTL to the tightest value compatible with your agent-to-agent latency. Default is 300 seconds. Most internal calls should tolerate 30 to 60 seconds.

---

## Transport Security

- [ ] Bind context envelopes to the mTLS channel between agents. Include the TLS session token fingerprint as an additional JWT claim.
- [ ] Enforce mTLS on all MCP tool call channels. Reject plaintext or TLS-only channels for high-trust tool endpoints.
- [ ] Validate that the agent identity in the JWT `iss` claim matches the mTLS client certificate subject.

---

## Per-Agent Trust Scope Enforcement

- [ ] Register each agent with a `max_trust_level` in the key registry that reflects its maximum permitted authority.
- [ ] Extend `mcp_validator.py` to reject envelopes where the claimed trust level exceeds the signer's registered maximum. This prevents a compromised web-scraper agent from signing a RESTRICTED envelope even if it obtains a valid key.
- [ ] Audit agent registrations quarterly. Remove stale agents.

---

## Observability

- [ ] Emit a structured log event for every validation gate decision (pass and reject). Include: tool_id, agent_id, trust_level, source_uri, decision, rejection_reason, latency_ms.
- [ ] Alert on sustained validation rejection rates above 1% for a given agent. This pattern indicates either misconfiguration or an active poisoning attempt.
- [ ] Forward validation logs to your SIEM. Map rejection events to MITRE ATLAS AML.T0051 and AML.T0054.
- [ ] Track per-agent signing volume. Anomalous spikes may indicate key compromise.

---

## Integration Testing

- [ ] Test every trust level combination in your production tool graph before deploying. Use the matrix in `trust_levels.py` as a starting point.
- [ ] Add a canary agent that periodically submits PUBLIC-signed envelopes to every INTERNAL-minimum tool and alerts if any pass.
- [ ] Include key expiry and rotation scenarios in your runbook. Verify that rolling a key does not drop valid in-flight envelopes.
- [ ] Run `demo_poisoning_rejected.py` as a smoke test in your CI pipeline against every tool deployment.

---

## MCP Server Integration

The PoC runs standalone. To integrate with a specific MCP server implementation:

- [ ] **Claude (Anthropic):** Wrap MCP tool response handlers with `ContextSigner.sign()` at the server layer. Add a middleware hook in the tool dispatcher that calls `ContextValidator.validate()` before passing context to any tool with `minimum_trust_level > PUBLIC`.
- [ ] **LangChain agents:** Override `BaseTool.run()` with a signed context wrapper. Add a `SignedContextCallback` to the agent executor.
- [ ] **AutoGen:** Implement a custom `ConversableAgent` message handler that signs outbound context and validates inbound context before `generate_reply()`.
- [ ] **Custom MCP servers:** Add the validation gate as middleware at the point where the MCP server dispatches tool calls. This is the cleanest integration point regardless of framework.
