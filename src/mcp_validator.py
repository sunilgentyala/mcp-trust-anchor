"""
mcp_validator.py
mcp-trust-anchor | github.com/sunilgentyala/mcp-trust-anchor

Validation gate for high-trust MCP tools. Verifies inbound context envelopes
before any payload content is processed or acted upon.

A tool declares its minimum acceptable trust level at instantiation. Any envelope
that fails signature verification or falls below that threshold is rejected with
a structured ValidationResult. The tool never touches the payload content until
the gate passes.

Usage:
    from mcp_validator import ContextValidator, ValidationResult
    from context_signer import TrustLevel

    validator = ContextValidator(
        tool_id="internal_code_executor",
        minimum_trust_level=TrustLevel.INTERNAL,
        key_registry={"web_scraper_agent": open("keys/web_scraper_agent_public.pem").read()},
    )

    result = validator.validate(signed_envelope_jwt)

    if not result.valid:
        raise PermissionError(f"Context rejected: {result.reason}")

    payload = result.payload  # Safe to use only after validation passes

Author: Sunil Gentyala
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from context_signer import TrustLevel


@dataclass
class ValidationResult:
    """
    Structured result from the context validation gate.

    Attributes:
        valid:       True only if ALL checks pass.
        reason:      Human-readable rejection reason. Empty string when valid.
        agent_id:    Identity of the signing agent (when signature is valid).
        trust_level: Trust level asserted by the signer.
        source_uri:  Origin URI declared by the signer.
        payload:     The MCP response content. None until validation passes.
                     Never access this field without checking valid == True first.
    """
    valid: bool
    reason: str = ""
    agent_id: Optional[str] = None
    trust_level: Optional[TrustLevel] = None
    source_uri: Optional[str] = None
    payload: Optional[dict] = None

    def __bool__(self) -> bool:
        return self.valid


class ContextValidator:
    """
    Validation gate for a high-trust MCP tool.

    Performs three sequential checks on every inbound context envelope:

    1. SIGNATURE VERIFICATION
       Decodes the JWT using the signing agent's registered public key.
       An unknown agent_id or invalid signature immediately rejects the envelope.

    2. EXPIRY CHECK
       Enforces the envelope TTL declared by the signer. Expired envelopes
       are rejected regardless of signature validity.

    3. TRUST LEVEL ENFORCEMENT
       Compares the envelope's declared trust level against this tool's
       minimum acceptable threshold. A PUBLIC envelope never reaches a
       tool that requires INTERNAL or above.

    4. PAYLOAD INTEGRITY CHECK
       Recomputes the SHA-256 digest of the payload content and compares
       it against the digest embedded in the JWT claims. This detects any
       tampering that occurred after signing.

    All four checks must pass. Failure at any step produces a ValidationResult
    with valid=False and a structured rejection reason.
    """

    ALGORITHM = "ES256"

    def __init__(
        self,
        tool_id: str,
        minimum_trust_level: TrustLevel,
        key_registry: dict,
    ) -> None:
        """
        Args:
            tool_id:              Identifier for this high-trust tool (for logging).
            minimum_trust_level:  The lowest trust level this tool will accept.
                                  Envelopes below this level are rejected without
                                  inspecting payload content.
            key_registry:         Dict mapping agent_id -> PEM-encoded public key string.
                                  In production: replace with a PKI-backed registry.
        """
        self.tool_id = tool_id
        self.minimum_trust_level = minimum_trust_level
        self._key_registry = {
            agent_id: load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
            for agent_id, pem in key_registry.items()
        }

    def validate(self, signed_envelope: str) -> ValidationResult:
        """
        Validate an inbound signed MCP context envelope.

        Args:
            signed_envelope: The compact JWT string produced by context_signer.py.

        Returns:
            ValidationResult with valid=True and extracted payload if all checks pass.
            ValidationResult with valid=False and rejection reason otherwise.
        """
        # Step 1: Extract agent identity without verifying signature yet.
        # We need the agent_id claim to look up the correct public key.
        try:
            unverified_header = jwt.get_unverified_header(signed_envelope)
            unverified_claims = jwt.decode(
                signed_envelope,
                options={"verify_signature": False},
            )
        except jwt.DecodeError as exc:
            return ValidationResult(
                valid=False,
                reason=f"Envelope is not a valid JWT: {exc}",
            )

        agent_id = unverified_claims.get("iss")
        if not agent_id:
            return ValidationResult(
                valid=False,
                reason="Envelope missing 'iss' (agent identity) claim.",
            )

        # Step 2: Look up the agent's public key.
        public_key = self._key_registry.get(agent_id)
        if public_key is None:
            return ValidationResult(
                valid=False,
                reason=(
                    f"Agent '{agent_id}' is not registered in the key registry. "
                    "Unsigned or unknown agents are not permitted."
                ),
            )

        # Step 3: Verify signature and standard JWT claims (expiry, issued-at).
        try:
            claims = jwt.decode(
                signed_envelope,
                public_key,
                algorithms=[self.ALGORITHM],
            )
        except jwt.ExpiredSignatureError:
            return ValidationResult(
                valid=False,
                agent_id=agent_id,
                reason=f"Context envelope from '{agent_id}' has expired.",
            )
        except jwt.InvalidSignatureError:
            return ValidationResult(
                valid=False,
                agent_id=agent_id,
                reason=(
                    f"Signature verification FAILED for agent '{agent_id}'. "
                    "The envelope may have been tampered with in transit."
                ),
            )
        except jwt.PyJWTError as exc:
            return ValidationResult(
                valid=False,
                agent_id=agent_id,
                reason=f"JWT validation error: {exc}",
            )

        # Step 4: Extract and validate MCP-specific claims.
        raw_trust_level = claims.get("mcp_trust_level")
        source_uri = claims.get("mcp_source_uri", "unknown")
        payload_digest = claims.get("mcp_payload_digest")
        mcp_payload = claims.get("mcp_payload")

        if raw_trust_level is None or mcp_payload is None or payload_digest is None:
            return ValidationResult(
                valid=False,
                agent_id=agent_id,
                reason="Envelope is missing required MCP trust boundary claims.",
            )

        try:
            trust_level = TrustLevel(raw_trust_level)
        except ValueError:
            return ValidationResult(
                valid=False,
                agent_id=agent_id,
                reason=f"Unknown trust level value: {raw_trust_level}",
            )

        # Step 5: Enforce minimum trust threshold.
        if trust_level < self.minimum_trust_level:
            return ValidationResult(
                valid=False,
                agent_id=agent_id,
                trust_level=trust_level,
                source_uri=source_uri,
                reason=(
                    f"TRUST BOUNDARY VIOLATION: Tool '{self.tool_id}' requires "
                    f"{self.minimum_trust_level.name} (level {int(self.minimum_trust_level)}) "
                    f"but received {trust_level.name} (level {int(trust_level)}) "
                    f"from agent '{agent_id}' sourced at '{source_uri}'. "
                    "Cross-boundary context poisoning attempt blocked."
                ),
            )

        # Step 6: Verify payload integrity.
        canonical = json.dumps(mcp_payload, sort_keys=True, separators=(",", ":"))
        recomputed_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if recomputed_digest != payload_digest:
            return ValidationResult(
                valid=False,
                agent_id=agent_id,
                trust_level=trust_level,
                source_uri=source_uri,
                reason=(
                    f"Payload integrity check FAILED for envelope from '{agent_id}'. "
                    "The payload content does not match the signed digest. "
                    "Envelope was modified after signing."
                ),
            )

        # All checks passed.
        return ValidationResult(
            valid=True,
            agent_id=agent_id,
            trust_level=trust_level,
            source_uri=source_uri,
            payload=mcp_payload,
        )

    def __repr__(self) -> str:
        registered_agents = list(self._key_registry.keys())
        return (
            f"ContextValidator("
            f"tool_id={self.tool_id!r}, "
            f"minimum_trust_level={self.minimum_trust_level.name!r}, "
            f"registered_agents={registered_agents!r})"
        )


# ---------------------------------------------------------------------------
# Example usage (run directly for a quick integration test)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    from pathlib import Path
    from context_signer import ContextSigner

    print("mcp-trust-anchor | mcp_validator.py integration test")
    print("-" * 54)

    private_key_path = "keys/demo_agent_private.pem"
    public_key_path = "keys/demo_agent_public.pem"

    if not Path(private_key_path).exists():
        print(
            f"Keys not found. Run: python keys/generate_keys.py --agent-id demo_agent"
        )
        sys.exit(1)

    public_key_pem = Path(public_key_path).read_text()

    signer = ContextSigner(
        agent_id="demo_agent",
        private_key_path=private_key_path,
        source_uri="https://public-external-source.example.com/feed",
    )

    validator = ContextValidator(
        tool_id="internal_code_executor",
        minimum_trust_level=TrustLevel.INTERNAL,
        key_registry={"demo_agent": public_key_pem},
    )

    # Test 1: PUBLIC context rejected by INTERNAL tool
    print("\n[Test 1] PUBLIC context sent to an INTERNAL-minimum tool")
    envelope = signer.sign(
        mcp_response={"content": "external data that may be adversarial"},
        trust_level=TrustLevel.PUBLIC,
    )
    result = validator.validate(envelope)
    print(f"  Valid: {result.valid}")
    print(f"  Reason: {result.reason}")
    assert not result.valid, "Expected rejection did not occur."

    # Test 2: INTERNAL context passes validation
    print("\n[Test 2] INTERNAL context sent to an INTERNAL-minimum tool")
    internal_signer = ContextSigner(
        agent_id="demo_agent",
        private_key_path=private_key_path,
        source_uri="https://internal-service.corp.example.com/api",
    )
    envelope = internal_signer.sign(
        mcp_response={"action": "run_query", "params": {"table": "users"}},
        trust_level=TrustLevel.INTERNAL,
    )
    result = validator.validate(envelope)
    print(f"  Valid: {result.valid}")
    if result.valid:
        print(f"  Payload accessible: {result.payload}")
    assert result.valid, f"Unexpected rejection: {result.reason}"

    # Test 3: Tampered payload detected
    print("\n[Test 3] Tampered payload (digest mismatch)")
    tampered = envelope[:-10] + "AAAAAAAAAA"  # corrupt the signature
    result = validator.validate(tampered)
    print(f"  Valid: {result.valid}")
    print(f"  Reason: {result.reason}")
    assert not result.valid, "Tampered payload was not rejected."

    print("\nAll tests passed.")
