"""
QuantumShield Quantum Readiness Scanner

Inspects TLS configurations of external domains to assess quantum vulnerability.
"""

from app.scanner.tls_scanner import QuantumReadinessScanner

__all__ = ["QuantumReadinessScanner"]
