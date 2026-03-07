"""
PKCE (Proof Key for Code Exchange) Implementation

Implements RFC 7636 PKCE for the OIDC Authorization Code Flow.
"""

import hashlib
import base64
import os


class PKCEVerifier:
    """
    PKCE Challenge/Verifier implementation per RFC 7636.
    
    Supports S256 challenge method (SHA-256).
    """

    @staticmethod
    def generate_code_verifier(length: int = 64) -> str:
        """
        Generate a cryptographically random code verifier.
        
        Args:
            length: Length of the verifier (43-128 characters per RFC 7636).
            
        Returns:
            URL-safe base64 encoded random string.
        """
        random_bytes = os.urandom(length)
        return base64.urlsafe_b64encode(random_bytes).rstrip(b"=").decode("ascii")[:128]

    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """
        Generate a code challenge from a code verifier using S256 method.
        
        Args:
            code_verifier: The code verifier string.
            
        Returns:
            Base64url-encoded SHA-256 hash of the verifier.
        """
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    @staticmethod
    def verify_challenge(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
        """
        Verify that a code verifier matches the stored challenge.
        
        Args:
            code_verifier: The verifier provided during token exchange.
            code_challenge: The challenge stored during authorization.
            method: The challenge method (only S256 supported).
            
        Returns:
            True if the verifier matches the challenge.
        """
        if method != "S256":
            raise ValueError(f"Unsupported code_challenge_method: {method}. Only S256 is supported.")

        computed_challenge = PKCEVerifier.generate_code_challenge(code_verifier)
        return computed_challenge == code_challenge
