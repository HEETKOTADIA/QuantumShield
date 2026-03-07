"""
Dilithium3 Digital Signature Scheme

Uses liboqs-python for NIST standardized post-quantum digital signatures.
"""

import oqs
from dataclasses import dataclass
from typing import Optional


@dataclass
class DilithiumKeyPair:
    """Represents a Dilithium3 key pair."""
    public_key: bytes
    secret_key: bytes
    algorithm: str = "Dilithium3"


class DilithiumSigner:
    """
    Dilithium3 Digital Signature Scheme.
    
    Provides key generation, signing, and verification using
    the NIST standardized ML-DSA (Dilithium) algorithm via liboqs.
    """

    # ML-DSA-65 is the NIST standardized name for Dilithium3
    ALGORITHM = "ML-DSA-65"
    DISPLAY_NAME = "Dilithium3"

    def __init__(self, secret_key: Optional[bytes] = None) -> None:
        self._secret_key = secret_key

    def generate_keypair(self) -> DilithiumKeyPair:
        """
        Generate a new Dilithium3 key pair.
        
        Returns:
            DilithiumKeyPair with public and secret keys.
        """
        sig = oqs.Signature(self.ALGORITHM)
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        self._secret_key = secret_key
        return DilithiumKeyPair(
            public_key=public_key,
            secret_key=secret_key,
            algorithm=self.ALGORITHM,
        )

    def sign(self, message: bytes, secret_key: Optional[bytes] = None) -> bytes:
        """
        Sign a message using Dilithium3.
        
        Args:
            message: The message bytes to sign.
            secret_key: Optional secret key. Uses stored key if not provided.
            
        Returns:
            The signature bytes.
        """
        sk = secret_key or self._secret_key
        if sk is None:
            raise ValueError("No secret key available. Generate a keypair first or provide a secret key.")
        sig = oqs.Signature(self.ALGORITHM, sk)
        signature = sig.sign(message)
        return signature

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a Dilithium3 signature.
        
        Args:
            message: The original message bytes.
            signature: The signature to verify.
            public_key: The signer's public key.
            
        Returns:
            True if the signature is valid, False otherwise.
        """
        sig = oqs.Signature(self.ALGORITHM)
        try:
            is_valid = sig.verify(message, signature, public_key)
            return is_valid
        except Exception:
            return False

    @staticmethod
    def get_algorithm_details() -> dict:
        """Get details about the Dilithium3 algorithm."""
        sig = oqs.Signature("ML-DSA-65")
        details = sig.details
        return {
            "name": "Dilithium3",
            "nist_name": "ML-DSA-65",
            "version": details.get("version", "NIST Standard"),
            "claimed_nist_level": details.get("claimed_nist_level", 3),
            "public_key_length": details.get("length_public_key", 0),
            "secret_key_length": details.get("length_secret_key", 0),
            "signature_length": details.get("length_signature", 0),
        }
