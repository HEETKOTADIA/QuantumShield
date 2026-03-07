"""
Quantum Readiness Scanner

Inspects TLS configurations of external domains to assess quantum vulnerability.
Connects via TLS, inspects certificates, and classifies algorithms.
"""

import ssl
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class QuantumReadiness(str, Enum):
    """Quantum readiness classification."""
    VULNERABLE = "quantum_vulnerable"
    RESISTANT = "quantum_resistant"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


# Algorithm classification mapping
ALGORITHM_CLASSIFICATION = {
    # Quantum Vulnerable
    "RSA": QuantumReadiness.VULNERABLE,
    "rsaEncryption": QuantumReadiness.VULNERABLE,
    "sha256WithRSAEncryption": QuantumReadiness.VULNERABLE,
    "sha384WithRSAEncryption": QuantumReadiness.VULNERABLE,
    "sha512WithRSAEncryption": QuantumReadiness.VULNERABLE,
    "ECDSA": QuantumReadiness.VULNERABLE,
    "ecdsa-with-SHA256": QuantumReadiness.VULNERABLE,
    "ecdsa-with-SHA384": QuantumReadiness.VULNERABLE,
    "ECDHE": QuantumReadiness.VULNERABLE,
    "DHE": QuantumReadiness.VULNERABLE,
    "DSA": QuantumReadiness.VULNERABLE,
    # Quantum Resistant
    "ML-KEM": QuantumReadiness.RESISTANT,
    "Kyber": QuantumReadiness.RESISTANT,
    "Dilithium": QuantumReadiness.RESISTANT,
    "ML-DSA": QuantumReadiness.RESISTANT,
    "FALCON": QuantumReadiness.RESISTANT,
    "SPHINCS+": QuantumReadiness.RESISTANT,
}


@dataclass
class ScanResult:
    """Result of scanning a single domain."""
    domain: str
    port: int = 443
    scan_time: float = 0.0
    tls_version: str = ""
    cipher_suite: str = ""
    cipher_bits: int = 0
    certificate_subject: str = ""
    certificate_issuer: str = ""
    certificate_algorithm: str = ""
    key_type: str = ""
    key_bits: int = 0
    san_domains: list[str] = field(default_factory=list)
    quantum_readiness: QuantumReadiness = QuantumReadiness.UNKNOWN
    vulnerabilities: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    error: Optional[str] = None
    scan_duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "port": self.port,
            "scan_time": self.scan_time,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "cipher_bits": self.cipher_bits,
            "certificate": {
                "subject": self.certificate_subject,
                "issuer": self.certificate_issuer,
                "algorithm": self.certificate_algorithm,
                "key_type": self.key_type,
                "key_bits": self.key_bits,
                "san_domains": self.san_domains,
            },
            "quantum_readiness": self.quantum_readiness.value,
            "vulnerabilities": self.vulnerabilities,
            "recommendations": self.recommendations,
            "error": self.error,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
        }


class QuantumReadinessScanner:
    """
    Scans TLS configurations of external domains and classifies
    their quantum readiness.
    """

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def _classify_algorithm(self, algorithm: str) -> QuantumReadiness:
        """Classify an algorithm's quantum readiness."""
        for key, readiness in ALGORITHM_CLASSIFICATION.items():
            if key.lower() in algorithm.lower():
                return readiness
        return QuantumReadiness.UNKNOWN

    def _extract_cert_info(self, cert: dict, result: ScanResult) -> None:
        """Extract certificate information."""
        # Subject
        subject = cert.get("subject", ())
        subject_parts = []
        for rdn in subject:
            for attr in rdn:
                subject_parts.append(f"{attr[0]}={attr[1]}")
        result.certificate_subject = ", ".join(subject_parts)

        # Issuer
        issuer = cert.get("issuer", ())
        issuer_parts = []
        for rdn in issuer:
            for attr in rdn:
                issuer_parts.append(f"{attr[0]}={attr[1]}")
        result.certificate_issuer = ", ".join(issuer_parts)

        # SAN
        san = cert.get("subjectAltName", ())
        result.san_domains = [name for _, name in san]

    def scan_domain(self, domain: str, port: int = 443) -> ScanResult:
        """
        Scan a domain's TLS configuration.
        
        Args:
            domain: The domain name to scan.
            port: The port to connect to (default 443).
            
        Returns:
            ScanResult with TLS configuration details.
        """
        result = ScanResult(domain=domain, port=port, scan_time=time.time())
        start = time.perf_counter()

        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # TLS version
                    result.tls_version = ssock.version() or "Unknown"

                    # Cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        result.cipher_suite = cipher[0]
                        result.cipher_bits = cipher[2] if len(cipher) > 2 else 0

                    # Certificate
                    cert = ssock.getpeercert()
                    if cert:
                        self._extract_cert_info(cert, result)

                    # Get binary cert for algorithm detection
                    bin_cert = ssock.getpeercert(binary_form=True)
                    if bin_cert:
                        try:
                            from cryptography import x509
                            parsed = x509.load_der_x509_certificate(bin_cert)
                            result.certificate_algorithm = parsed.signature_algorithm_oid._name
                            pub_key = parsed.public_key()
                            result.key_bits = pub_key.key_size  # type: ignore
                            result.key_type = type(pub_key).__name__.replace("_", " ")
                        except Exception:
                            result.certificate_algorithm = "Unknown"

            # Classify quantum readiness
            algo_readiness = self._classify_algorithm(result.certificate_algorithm)
            cipher_readiness = self._classify_algorithm(result.cipher_suite)

            if algo_readiness == QuantumReadiness.RESISTANT and cipher_readiness == QuantumReadiness.RESISTANT:
                result.quantum_readiness = QuantumReadiness.RESISTANT
            elif algo_readiness == QuantumReadiness.RESISTANT or cipher_readiness == QuantumReadiness.RESISTANT:
                result.quantum_readiness = QuantumReadiness.HYBRID
            elif algo_readiness == QuantumReadiness.VULNERABLE or cipher_readiness == QuantumReadiness.VULNERABLE:
                result.quantum_readiness = QuantumReadiness.VULNERABLE
            else:
                result.quantum_readiness = QuantumReadiness.UNKNOWN

            # Generate vulnerability notes
            if result.quantum_readiness == QuantumReadiness.VULNERABLE:
                if "RSA" in result.certificate_algorithm or "rsa" in result.certificate_algorithm.lower():
                    result.vulnerabilities.append(
                        f"RSA signature ({result.certificate_algorithm}) is vulnerable to Shor's algorithm"
                    )
                if "ECDSA" in result.certificate_algorithm or "ecdsa" in result.certificate_algorithm.lower():
                    result.vulnerabilities.append(
                        f"ECDSA signature ({result.certificate_algorithm}) is vulnerable to quantum attacks"
                    )
                if "ECDHE" in result.cipher_suite or "DHE" in result.cipher_suite:
                    result.vulnerabilities.append(
                        f"Key exchange ({result.cipher_suite}) uses quantum-vulnerable Diffie-Hellman"
                    )
                result.recommendations.append("Migrate to post-quantum algorithms (ML-KEM, ML-DSA)")
                result.recommendations.append("Consider hybrid PQ/classical key exchange")
                result.recommendations.append("Plan migration timeline before cryptographically relevant quantum computers")

        except ssl.SSLError as e:
            result.error = f"SSL Error: {str(e)}"
        except socket.timeout:
            result.error = "Connection timed out"
        except socket.gaierror:
            result.error = f"DNS resolution failed for {domain}"
        except ConnectionRefusedError:
            result.error = f"Connection refused by {domain}:{port}"
        except Exception as e:
            result.error = f"Scan error: {str(e)}"

        result.scan_duration_ms = (time.perf_counter() - start) * 1000
        return result

    def scan_multiple(self, domains: list[str], port: int = 443) -> list[ScanResult]:
        """Scan multiple domains."""
        return [self.scan_domain(domain, port) for domain in domains]
