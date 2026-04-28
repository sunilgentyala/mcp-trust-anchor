"""
key_registry.py
mcp-trust-anchor | github.com/sunilgentyala/mcp-trust-anchor

In-memory public key registry stub.

Maps agent identifiers to their ECDSA P-256 public keys and permitted
trust scopes. In production, replace this with a PKI-backed registry
(e.g. backed by AWS ACM, Vault PKI, or an internal SPIFFE/SPIRE deployment).

This module is intentionally simple. It loads PEM files from disk at
startup and serves them from memory. It does not handle key rotation,
revocation, or distributed synchronization.
"""

import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from trust_levels import TrustLevel


class AgentRegistration:
    """
    A single agent entry in the key registry.

    Attributes:
        agent_id:        Unique agent identifier. Must match the 'iss' claim
                         in signed JWT envelopes.
        public_key:      Loaded ECDSA P-256 public key object.
        max_trust_level: The highest trust level this agent is permitted to assert.
                         An agent registered with max_trust_level=INTERNAL cannot
                         sign a CONFIDENTIAL or RESTRICTED envelope. The validator
                         enforces this separately from the tool's minimum threshold.
        description:     Human-readable description of the agent's role.
    """

    def __init__(
        self,
        agent_id: str,
        public_key: EllipticCurvePublicKey,
        max_trust_level: TrustLevel = TrustLevel.PUBLIC,
        description: str = "",
    ) -> None:
        self.agent_id = agent_id
        self.public_key = public_key
        self.max_trust_level = max_trust_level
        self.description = description

    def __repr__(self) -> str:
        return (
            f"AgentRegistration(agent_id={self.agent_id!r}, "
            f"max_trust_level={self.max_trust_level.name})"
        )


class KeyRegistry:
    """
    In-memory public key registry for MCP trust anchor validation.

    Usage:
        registry = KeyRegistry()
        registry.register_from_pem(
            agent_id="web_scraper_agent",
            pem_path="keys/web_scraper_agent_public.pem",
            max_trust_level=TrustLevel.PUBLIC,
        )
        public_key = registry.get_public_key("web_scraper_agent")

    Production note: Replace disk-based PEM loading with calls to a
    secrets manager or PKI API. Add a refresh interval to pick up
    rotated keys without restarting the service.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentRegistration] = {}

    def register(
        self,
        agent_id: str,
        public_key: EllipticCurvePublicKey,
        max_trust_level: TrustLevel = TrustLevel.PUBLIC,
        description: str = "",
    ) -> None:
        """Register an agent with a pre-loaded public key object."""
        self._agents[agent_id] = AgentRegistration(
            agent_id=agent_id,
            public_key=public_key,
            max_trust_level=max_trust_level,
            description=description,
        )

    def register_from_pem(
        self,
        agent_id: str,
        pem_path: str,
        max_trust_level: TrustLevel = TrustLevel.PUBLIC,
        description: str = "",
    ) -> None:
        """Load a PEM file from disk and register the agent."""
        path = Path(pem_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Public key not found at {pem_path}. "
                "Run: python keys/generate_keys.py --agent-id <id>"
            )
        raw = path.read_bytes()
        public_key = load_pem_public_key(raw)
        self.register(agent_id, public_key, max_trust_level, description)

    def register_from_pem_string(
        self,
        agent_id: str,
        pem_string: str,
        max_trust_level: TrustLevel = TrustLevel.PUBLIC,
        description: str = "",
    ) -> None:
        """Register an agent from a PEM string (e.g. loaded from a secrets manager)."""
        raw = pem_string.encode() if isinstance(pem_string, str) else pem_string
        public_key = load_pem_public_key(raw)
        self.register(agent_id, public_key, max_trust_level, description)

    def get_public_key(self, agent_id: str) -> Optional[EllipticCurvePublicKey]:
        """Return the public key for an agent, or None if not registered."""
        reg = self._agents.get(agent_id)
        return reg.public_key if reg else None

    def get_registration(self, agent_id: str) -> Optional[AgentRegistration]:
        """Return the full AgentRegistration for an agent, or None."""
        return self._agents.get(agent_id)

    def is_registered(self, agent_id: str) -> bool:
        return agent_id in self._agents

    def as_dict(self) -> dict:
        """Return a plain dict of agent_id -> public_key for use with ContextValidator."""
        return {agent_id: reg.public_key for agent_id, reg in self._agents.items()}

    def list_agents(self) -> list[str]:
        return list(self._agents.keys())

    def __len__(self) -> int:
        return len(self._agents)

    def __repr__(self) -> str:
        return f"KeyRegistry(agents={self.list_agents()!r})"


def load_registry_from_keys_dir(
    keys_dir: str = "keys",
    max_trust_level: TrustLevel = TrustLevel.PUBLIC,
) -> KeyRegistry:
    """
    Convenience loader: scans a directory for *_public.pem files and
    registers each one automatically using the filename stem as the agent_id.

    Example: keys/web_scraper_agent_public.pem -> agent_id = "web_scraper_agent"
    """
    registry = KeyRegistry()
    keys_path = Path(keys_dir)
    for pem_file in sorted(keys_path.glob("*_public.pem")):
        agent_id = pem_file.stem.replace("_public", "")
        registry.register_from_pem(
            agent_id=agent_id,
            pem_path=str(pem_file),
            max_trust_level=max_trust_level,
        )
    return registry


if __name__ == "__main__":
    print("mcp-trust-anchor | key_registry.py smoke test")
    print("-" * 50)
    registry = load_registry_from_keys_dir("keys")
    if not registry:
        print("No keys found in keys/. Run: python keys/generate_keys.py --agent-id demo_agent")
    else:
        print(f"Loaded {len(registry)} agent(s): {registry.list_agents()}")
        for agent_id in registry.list_agents():
            reg = registry.get_registration(agent_id)
            print(f"  {agent_id}: max_trust={reg.max_trust_level.name}, key={type(reg.public_key).__name__}")
