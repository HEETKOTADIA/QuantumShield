"""
QuantumShield Post-Quantum Cryptography Module

Provides Kyber768 (ML-KEM) key encapsulation and Dilithium3 digital signatures
using the Open Quantum Safe (liboqs) library.
"""

from app.pqcrypto.kem import KyberKEM
from app.pqcrypto.signatures import DilithiumSigner

__all__ = ["KyberKEM", "DilithiumSigner"]
