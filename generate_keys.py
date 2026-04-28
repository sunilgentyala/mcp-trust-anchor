"""
generate_keys.py
mcp-trust-anchor | github.com/sunilgentyala/mcp-trust-anchor

Generates an ECDSA P-256 key pair for a named agent.
Writes private and public keys as PEM files under the keys/ directory.

Usage:
    python keys/generate_keys.py --agent-id web_scraper_agent

Output:
    keys/web_scraper_agent_private.pem  (KEEP PRIVATE, never commit)
    keys/web_scraper_agent_public.pem   (distribute to validators)

Production note: In a real deployment, generate private keys inside an HSM
or secrets manager. Never write private key material to disk in plaintext.
"""

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_key_pair(agent_id: str, output_dir: str = "keys") -> None:
    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = out / f"{agent_id}_private.pem"
    public_path = out / f"{agent_id}_public.pem"

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    print(f"Key pair generated for agent '{agent_id}':")
    print(f"  Private key: {private_path}  <-- NEVER COMMIT THIS FILE")
    print(f"  Public key:  {public_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate ECDSA P-256 key pair for an MCP agent.")
    parser.add_argument("--agent-id", required=True, help="Unique agent identifier")
    parser.add_argument("--output-dir", default="keys", help="Output directory (default: keys/)")
    args = parser.parse_args()
    generate_key_pair(args.agent_id, args.output_dir)
