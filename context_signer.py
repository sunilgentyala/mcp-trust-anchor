"""
context_signer.py
mcp-trust-anchor | github.com/sunilgentyala/mcp-trust-anchor

Signs MCP tool response payloads in a JWT envelope asserting cryptographic
trust boundary metadata. Uses ECDSA P-256 (ES256) via the PyJWT library.

Usage:
    from context_signer import ContextSigner, TrustLevel

    signer = ContextSigner(
        agent_id="web_scraper_agent",
        private_key_path="keys/web_scraper_agent_private.pem",
        source_uri="https://external-source.example.com/data"
    )

    signed_payload = signer.sign(
        mcp_response={"result": "some external content"},
        trust_level=TrustLevel.PUBLIC
    )

Author: Sunil Gentyala
"""

import hashlib
import json
import time
import uuid
from enum import IntEnum
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class TrustLevel(IntEnum):
    """
    Enumerated trust levels for MCP context payloads.

    Assign the level that reflects the ORIGIN of the data, not the
    identity of the agent processing it. A high-privilege agent that
    reads from a public web source must still tag output as PUBLIC.
    """
    PUBLIC = 1        # External web, unauthenticated APIs, RSS feeds
    INTERNAL = 2      # Authenticated internal services
    CONFIDENTIAL = 3  # Restricted internal systems, vetted databases
    RESTRICTED = 4    # Classified or regulated data stores


class ContextSigningError(Exception):
    """Raised when context signing fails."""
    pass


class ContextSigner:
    """
    Wraps an MCP tool response in a signed JWT envelope.

    The envelope asserts:
      - Agent identity (who generated this context)
      - Source URI (where the data came from)
      - Trust level (PUBLIC through RESTRICTED)
      - SHA-256 payload digest (tamper detection)
      - Issuance timestamp and expiry

    The receiving high-trust tool uses mcp_validator.py to verify
    this envelope before processing any payload content.
    """

    ALGORITHM = "ES256"
    DEFAULT_TTL_SECONDS = 300  # Context envelopes expire after 5 minutes

    def __init__(
        self,
        agent_id: str,
        private_key_path: str,
        source_uri: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        """
        Args:
            agent_id:         Unique identifier for the signing agent.
                              Must match an entry in the receiver's key registry.
            private_key_path: Path to the PEM-encoded ECDSA P-256 private key.
                              In production: load from HSM or secrets manager instead.
            source_uri:       URI of the data source this agent is reading from.
            ttl_seconds:      Seconds until the envelope expires. Default: 300.
        """
        self.agent_id = agent_id
        self.source_uri = source_uri
        self.ttl_seconds = ttl_seconds
        self._private_key = self._load_private_key(private_key_path)

    def _load_private_key(self, path: str) -> Any:
        key_path = Path(path)
        if not key_path.exists():
            raise ContextSigningError(
                f"Private key not found at {path}. "
                "Run: python keys/generate_keys.py --agent-id <id>"
            )
        raw = key_path.read_bytes()
        return load_pem_private_key(raw, password=None)

    def _digest_payload(self, mcp_response: dict) -> str:
        """
        Compute a SHA-256 digest of the canonical JSON representation
        of the MCP response payload.

        Canonical = keys sorted, no whitespace. Any modification to the
        payload after signing will produce a different digest and fail
        validation.
        """
        canonical = json.dumps(mcp_response, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def sign(self, mcp_response: dict, trust_level: TrustLevel) -> str:
        """
        Sign an MCP tool response and return a compact JWT string.

        Args:
            mcp_response: The raw dict returned by the MCP tool.
            trust_level:  The trust level appropriate for the source of this data.
                          The signer, not the receiver, determines this. Assign
                          the level that reflects the data origin.

        Returns:
            A compact JWT string (header.payload.signature) to be passed
            as the MCP context envelope to the receiving tool.

        Raises:
            ContextSigningError: If signing fails for any reason.
        """
        now = int(time.time())
        jti = str(uuid.uuid4())
        payload_digest = self._digest_payload(mcp_response)

        claims = {
            # Standard JWT claims
            "iss": self.agent_id,             # Issuer: the signing agent
            "iat": now,                        # Issued at
            "exp": now + self.ttl_seconds,    # Expiry
            "jti": jti,                        # Unique token ID (replay prevention stub)

            # MCP trust boundary claims
            "mcp_source_uri": self.source_uri,
            "mcp_trust_level": int(trust_level),
            "mcp_trust_label": trust_level.name,
            "mcp_payload_digest": payload_digest,

            # The actual MCP response content
            "mcp_payload": mcp_response,
        }

        try:
            token = jwt.encode(
                claims,
                self._private_key,
                algorithm=self.ALGORITHM,
            )
        except Exception as exc:
            raise ContextSigningError(f"JWT signing failed: {exc}") from exc

        return token

    def __repr__(self) -> str:
        return (
            f"ContextSigner("
            f"agent_id={self.agent_id!r}, "
            f"source_uri={self.source_uri!r}, "
            f"algorithm={self.ALGORITHM!r})"
        )


# ---------------------------------------------------------------------------
# Example usage (run directly for a quick smoke test)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    print("mcp-trust-anchor | context_signer.py smoke test")
    print("-" * 52)

    # This requires a key pair to exist. Run generate_keys.py first.
    private_key_path = "keys/demo_agent_private.pem"
    public_key_path = "keys/demo_agent_public.pem"

    if not Path(private_key_path).exists():
        print(
            f"Key not found at {private_key_path}.\n"
            "Run: python keys/generate_keys.py --agent-id demo_agent"
        )
        sys.exit(1)

    signer = ContextSigner(
        agent_id="demo_agent",
        private_key_path=private_key_path,
        source_uri="https://public-external-source.example.com/feed",
    )

    sample_response = {
        "tool": "web_fetch",
        "content": "This is external content that could contain adversarial instructions.",
        "fetched_at": int(time.time()),
    }

    token = signer.sign(mcp_response=sample_response, trust_level=TrustLevel.PUBLIC)
    print(f"Signed context envelope (JWT):\n\n{token}\n")

    # Decode without verification to show claims (for demo purposes only)
    decoded = jwt.decode(token, options={"verify_signature": False})
    print("Decoded claims (unverified, for inspection):")
    for key, value in decoded.items():
        if key != "mcp_payload":
            print(f"  {key}: {value}")
    print(f"  mcp_payload: <{len(json.dumps(decoded['mcp_payload']))} bytes>")
    print("\nSigning complete. Pass this token to mcp_validator.py for verification.")
