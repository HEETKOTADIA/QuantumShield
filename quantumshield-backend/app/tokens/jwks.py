"""
JWKS (JSON Web Key Set) Provider

Publishes the Dilithium3 public key in JWKS format for token verification.
"""

import base64
from typing import Optional

from app.pqcrypto.signatures import DilithiumSigner


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class JWKSProvider:
    """
    JWKS endpoint provider for Dilithium3 public keys.
    
    Publishes the post-quantum signing key in a format compatible
    with JWKS conventions, extended for PQ algorithms.
    """

    def __init__(self, public_key: Optional[bytes] = None) -> None:
        self._public_key = public_key

    def set_public_key(self, public_key: bytes) -> None:
        """Set the Dilithium3 public key."""
        self._public_key = public_key

    def get_jwks(self) -> dict:
        """
        Get the JWKS document containing the Dilithium3 public key.
        
        Returns:
            JWKS document as a dict.
        """
        if self._public_key is None:
            return {"keys": []}

        key = {
            "kty": "PQC",
            "alg": "DILITHIUM3",
            "use": "sig",
            "kid": "quantumshield-dilithium3-key-1",
            "x": _b64url_encode(self._public_key),
            "key_ops": ["verify"],
            "pqc_algorithm": "Dilithium3",
            "nist_name": "ML-DSA-65",
            "key_size_bytes": len(self._public_key),
        }

        # Get algorithm details
        try:
            details = DilithiumSigner.get_algorithm_details()
            key["nist_level"] = details.get("claimed_nist_level", 3)
        except Exception:
            pass

        return {"keys": [key]}
