"""
examples/demo_sign_and_validate.py
mcp-trust-anchor | github.com/sunilgentyala/mcp-trust-anchor

End-to-end demonstration: sign an MCP context payload, pass it to a
high-trust tool, and validate the envelope before accessing the payload.

Run from the repo root:
    python keys/generate_keys.py --agent-id internal_service
    python examples/demo_sign_and_validate.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from context_signer import ContextSigner
from mcp_validator import ContextValidator
from trust_levels import TrustLevel

AGENT_ID       = "internal_service"
PRIVATE_KEY    = f"keys/{AGENT_ID}_private.pem"
PUBLIC_KEY     = f"keys/{AGENT_ID}_public.pem"

def main():
    print("=" * 60)
    print("mcp-trust-anchor | End-to-End Demo: Sign and Validate")
    print("=" * 60)

    if not Path(PRIVATE_KEY).exists():
        print(f"\nKey not found. Run first:")
        print(f"  python keys/generate_keys.py --agent-id {AGENT_ID}")
        sys.exit(1)

    # Step 1: An internal service agent signs its MCP tool response.
    print("\n[Step 1] Agent signs MCP context payload")
    signer = ContextSigner(
        agent_id=AGENT_ID,
        private_key_path=PRIVATE_KEY,
        source_uri="https://internal-api.corp.example.com/v1/data",
    )

    mcp_response = {
        "tool": "query_internal_db",
        "result": {"records": 42, "schema": "users", "latency_ms": 12},
        "fetched_at": int(time.time()),
    }

    signed = signer.sign(mcp_response, trust_level=TrustLevel.INTERNAL)
    print(f"  Agent ID   : {AGENT_ID}")
    print(f"  Trust level: INTERNAL")
    print(f"  Algorithm  : ES256 (ECDSA P-256)")
    print(f"  Token size : {len(signed)} bytes")

    # Step 2: A high-trust tool receives the envelope and validates it.
    print("\n[Step 2] High-trust tool validates envelope")
    public_key_pem = Path(PUBLIC_KEY).read_text()
    validator = ContextValidator(
        tool_id="privileged_executor",
        minimum_trust_level=TrustLevel.INTERNAL,
        key_registry={AGENT_ID: public_key_pem},
    )

    result = validator.validate(signed)

    if result.valid:
        print(f"  Signature  : VERIFIED")
        print(f"  Trust level: {result.trust_level.name} >= INTERNAL (min)")
        print(f"  Source URI : {result.source_uri}")
        print(f"  Payload    : {result.payload}")
        print("\n  Access granted. Payload ready for high-trust tool processing.")
    else:
        print(f"  REJECTED: {result.reason}")
        sys.exit(1)

    print()
    print("Demo complete. The signed envelope passed all four validation checks:")
    print("  1. ECDSA P-256 signature verified")
    print("  2. Envelope TTL within bounds")
    print("  3. Trust level INTERNAL >= minimum INTERNAL")
    print("  4. SHA-256 payload digest matched")

if __name__ == "__main__":
    main()
