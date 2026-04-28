
# mcp-trust-anchor

**Cryptographic context-signing proof-of-concept for MCP trust boundary enforcement.**

Companion repository for the Help Net Security column:
*"Cross-Boundary Context Poisoning: The Hidden Threat in the Model Context Protocol (MCP)"*
by Sunil Gentyala.

---

## The Problem

MCP context payloads carry no provenance metadata. A payload sourced from a public
web scrape is structurally identical to one sourced from a vetted internal knowledge
base. High-trust tools have no mechanism to distinguish them. This creates a direct
path for cross-boundary context poisoning and indirect privilege escalation.

## The Solution

This PoC wraps MCP tool responses in signed JWT envelopes that assert:

- **Trust level** (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)
- **Originating agent identity**
- **Source URI**
- **SHA-256 payload digest** (tamper detection)
- **Issuance timestamp**

High-trust tools validate this envelope before processing any inbound context.
Payloads that fail signature verification or fall below the tool's minimum trust
threshold are rejected with a structured error.

---

## Repository Structure

```
mcp-trust-anchor/
├── README.md
├── requirements.txt
├── keys/
│   ├── generate_keys.py        # ECDSA P-256 key pair generator
│   └── .gitignore              # Excludes private keys from commits
├── src/
│   ├── context_signer.py       # Signs MCP context payloads as JWT envelopes
│   ├── mcp_validator.py        # High-trust tool validation gate
│   ├── trust_levels.py         # Trust level enum and policy definitions
│   └── key_registry.py         # In-memory public key registry (stub)
├── examples/
│   ├── demo_sign_and_validate.py
│   └── demo_poisoning_rejected.py
└── docs/
    ├── threat_model.md
    └── production_checklist.md
```

---

## Quick Start

```bash
git clone https://github.com/sunilgentyala/mcp-trust-anchor
cd mcp-trust-anchor
pip install -r requirements.txt

# Generate a key pair for a sample agent
python keys/generate_keys.py --agent-id web_scraper_agent

# Run the sign-and-validate demo
python examples/demo_sign_and_validate.py

# Run the cross-boundary poisoning rejection demo
python examples/demo_poisoning_rejected.py
```

---

## Trust Level Policy

| Level        | Numeric | Permitted Sources                              |
|--------------|---------|------------------------------------------------|
| PUBLIC       | 1       | External web, unauthenticated APIs, RSS feeds  |
| INTERNAL     | 2       | Authenticated internal services                |
| CONFIDENTIAL | 3       | Restricted internal systems, vetted databases  |
| RESTRICTED   | 4       | Classified or regulated data stores            |

High-trust tools declare a **minimum acceptable level**. Payloads below that
threshold are rejected before any processing occurs.

---

## Signing Algorithm

All signatures use **ECDSA with P-256 (ES256)**. P-256 was selected for:

- Compact signature footprint (64 bytes) relative to RSA-2048
- Native hardware security module (HSM) support across major vendors
- Broad library support (cryptography, python-jose, PyJWT)

**Production note:** This PoC uses file-based PEM keys. Production deployments
should store private keys in an HSM or secrets manager (AWS KMS, Azure Key Vault,
HashiCorp Vault) and implement key rotation with a minimum 90-day cycle.

---

## What This PoC Does Not Cover

This repository is a signal-focused proof of concept. The following are
deliberately omitted to reduce noise:

- Distributed public key registry / PKI infrastructure
- Key rotation and revocation workflows
- Replay attack prevention (nonce registry)
- mTLS channel binding for MCP transport
- Integration with specific MCP server implementations (Claude, LangChain, AutoGen)

The `docs/production_checklist.md` file covers recommended controls for each
of these areas.

---

## Related Projects

- [ContextGuard](https://github.com/sunilgentyala/contextguard) - Zero-trust middleware for MCP security
- [GSH Framework](https://github.com/sunilgentyala/gsh-framework) - Agentic AI threat hunting mapped to MITRE ATLAS and NIST CSF 2.0

---

## Author

**Sunil Gentyala**
Lead Cybersecurity and AI Security Consultant, HCLTech
IEEE Senior Member | Cloud Security Alliance Representative
LinkedIn: [linkedin.com/in/sunil-gentyala](https://linkedin.com/in/sunil-gentyala)

---

## License

MIT License. See LICENSE for details.
