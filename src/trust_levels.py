"""
trust_levels.py
mcp-trust-anchor | github.com/sunilgentyala/mcp-trust-anchor

Trust level enumeration and policy definitions for MCP context envelopes.

Import this module directly instead of importing TrustLevel from
context_signer, so trust level logic stays decoupled from signing logic.
"""

from enum import IntEnum


class TrustLevel(IntEnum):
    """
    Enumerated trust levels for MCP context payloads.

    Assign the level that reflects the ORIGIN of the data, not the
    identity of the agent processing it. A high-privilege agent that
    reads from a public web source must still tag output as PUBLIC.

    Levels are ordinal: RESTRICTED (4) > CONFIDENTIAL (3) > INTERNAL (2) > PUBLIC (1).
    A tool that declares minimum_trust_level=INTERNAL accepts INTERNAL,
    CONFIDENTIAL, and RESTRICTED, but rejects PUBLIC.
    """
    PUBLIC       = 1   # External web, unauthenticated APIs, RSS feeds
    INTERNAL     = 2   # Authenticated internal services
    CONFIDENTIAL = 3   # Restricted internal systems, vetted databases
    RESTRICTED   = 4   # Classified or regulated data stores

    def label(self) -> str:
        return self.name

    def accepts(self, minimum: "TrustLevel") -> bool:
        """Return True if this trust level satisfies the given minimum."""
        return self >= minimum

    def __str__(self) -> str:
        return f"{self.name} (level {self.value})"


# Policy table: maps trust level to permitted source categories.
TRUST_POLICY = {
    TrustLevel.PUBLIC:       "External web, unauthenticated APIs, RSS feeds, public data",
    TrustLevel.INTERNAL:     "Authenticated internal services, vetted internal APIs",
    TrustLevel.CONFIDENTIAL: "Restricted internal systems, vetted databases, PII stores",
    TrustLevel.RESTRICTED:   "Classified or regulated data stores, HSM-gated sources",
}


def describe(level: TrustLevel) -> str:
    """Return the policy description for a given trust level."""
    return TRUST_POLICY.get(level, "Unknown trust level")


if __name__ == "__main__":
    print("mcp-trust-anchor | Trust Level Policy")
    print("-" * 48)
    for level in TrustLevel:
        print(f"  {level.value}  {level.name:<14} {describe(level)}")
    print()
    print("Acceptance matrix (row = payload level, col = tool minimum):")
    print(f"  {'':14}", end="")
    for col in TrustLevel:
        print(f"  min={col.name:<12}", end="")
    print()
    for row in TrustLevel:
        print(f"  {row.name:<14}", end="")
        for col in TrustLevel:
            accepted = "ACCEPT" if row.accepts(col) else "REJECT"
            print(f"  {accepted:<16}", end="")
        print()
