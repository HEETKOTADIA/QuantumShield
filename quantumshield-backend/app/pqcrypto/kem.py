"""
Kyber768 (ML-KEM) Key Encapsulation Mechanism

Uses liboqs-python for NIST standardized post-quantum KEM operations.
"""

import oqs
from dataclasses import dataclass
from typing import Optional


@dataclass
class KyberKeyPair:
    """Represents a Kyber768 key pair."""
    public_key: bytes
    secret_key: bytes
    algorithm: str = "Kyber768"


@dataclass
class KyberEncapsulationResult:
    """Result of a Kyber768 encapsulation operation."""
    ciphertext: bytes
    shared_secret: bytes
    algorithm: str = "Kyber768"


class KyberKEM:
    """
    Kyber768 (ML-KEM) Key Encapsulation Mechanism.
    
    Provides key generation, encapsulation, and decapsulation using
    the NIST standardized ML-KEM (Kyber) algorithm via liboqs.
    """

    ALGORITHM = "Kyber768"

    def __init__(self) -> None:
        self._kem: Optional[oqs.KeyEncapsulation] = None

    def generate_keypair(self) -> KyberKeyPair:
        """
        Generate a new Kyber768 key pair.
        
        Returns:
            KyberKeyPair with public and secret keys.
        """
        kem = oqs.KeyEncapsulation(self.ALGORITHM)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return KyberKeyPair(
            public_key=public_key,
            secret_key=secret_key,
            algorithm=self.ALGORITHM,
        )

    def encapsulate(self, public_key: bytes) -> KyberEncapsulationResult:
        """
        Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's Kyber768 public key.
            
        Returns:
            KyberEncapsulationResult with ciphertext and shared secret.
        """
        kem = oqs.KeyEncapsulation(self.ALGORITHM)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return KyberEncapsulationResult(
            ciphertext=ciphertext,
            shared_secret=shared_secret,
            algorithm=self.ALGORITHM,
        )

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate a shared secret using the secret key.
        
        Args:
            ciphertext: The ciphertext from encapsulation.
            secret_key: The recipient's Kyber768 secret key.
            
        Returns:
            The shared secret bytes.
        """
        kem = oqs.KeyEncapsulation(self.ALGORITHM, secret_key)
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    @staticmethod
    def get_algorithm_details() -> dict:
        """Get details about the Kyber768 algorithm."""
        kem = oqs.KeyEncapsulation("Kyber768")
        details = kem.details
        return {
            "name": "Kyber768",
            "nist_name": "ML-KEM-768",
            "version": details.get("version", "NIST Standard"),
            "claimed_nist_level": details.get("claimed_nist_level", 3),
            "public_key_length": details.get("length_public_key", 0),
            "secret_key_length": details.get("length_secret_key", 0),
            "ciphertext_length": details.get("length_ciphertext", 0),
            "shared_secret_length": details.get("length_shared_secret", 0),
        }
