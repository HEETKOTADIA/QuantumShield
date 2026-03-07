"""
Benchmarking Engine

Measures performance of post-quantum and classical cryptographic operations.
All timing uses time.perf_counter() for high-resolution measurements.
"""

import time
import statistics
from dataclasses import dataclass, field
from typing import Optional

import oqs
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.pqcrypto.kem import KyberKEM
from app.pqcrypto.signatures import DilithiumSigner
from app.kemtls.protocol import perform_kemtls_handshake
from app.tokens.engine import TokenEngine


@dataclass
class BenchmarkResult:
    """Result of a single benchmark operation."""
    operation: str
    algorithm: str
    category: str
    iterations: int
    times_ms: list[float] = field(default_factory=list)

    @property
    def mean_ms(self) -> float:
        return statistics.mean(self.times_ms) if self.times_ms else 0.0

    @property
    def median_ms(self) -> float:
        return statistics.median(self.times_ms) if self.times_ms else 0.0

    @property
    def min_ms(self) -> float:
        return min(self.times_ms) if self.times_ms else 0.0

    @property
    def max_ms(self) -> float:
        return max(self.times_ms) if self.times_ms else 0.0

    @property
    def stddev_ms(self) -> float:
        return statistics.stdev(self.times_ms) if len(self.times_ms) > 1 else 0.0

    def to_dict(self) -> dict:
        return {
            "operation": self.operation,
            "algorithm": self.algorithm,
            "category": self.category,
            "iterations": self.iterations,
            "mean_ms": round(self.mean_ms, 4),
            "median_ms": round(self.median_ms, 4),
            "min_ms": round(self.min_ms, 4),
            "max_ms": round(self.max_ms, 4),
            "stddev_ms": round(self.stddev_ms, 4),
        }


@dataclass
class BenchmarkSuite:
    """A collection of benchmark results."""
    results: list[BenchmarkResult] = field(default_factory=list)
    run_timestamp: float = field(default_factory=time.time)
    total_duration_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "run_timestamp": self.run_timestamp,
            "total_duration_s": round(self.total_duration_s, 2),
            "results": [r.to_dict() for r in self.results],
        }


class BenchmarkEngine:
    """
    Cryptographic Benchmarking Engine.
    
    Measures real performance of PQ and classical crypto operations
    with configurable iteration counts.
    """

    def __init__(self) -> None:
        self._kem = KyberKEM()
        self._signer = DilithiumSigner()

    def _bench(self, operation: str, algorithm: str, category: str, iterations: int, func: object) -> BenchmarkResult:
        """Run a benchmark for a given function."""
        result = BenchmarkResult(
            operation=operation,
            algorithm=algorithm,
            category=category,
            iterations=iterations,
        )
        for _ in range(iterations):
            start = time.perf_counter()
            func()  # type: ignore
            end = time.perf_counter()
            result.times_ms.append((end - start) * 1000)
        return result

    # --- Kyber768 Benchmarks ---

    def bench_kyber_keygen(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark Kyber768 key generation."""
        return self._bench("Key Generation", "Kyber768", "KEM", iterations, self._kem.generate_keypair)

    def bench_kyber_encapsulate(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark Kyber768 encapsulation."""
        keypair = self._kem.generate_keypair()
        return self._bench(
            "Encapsulation", "Kyber768", "KEM", iterations,
            lambda: self._kem.encapsulate(keypair.public_key),
        )

    def bench_kyber_decapsulate(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark Kyber768 decapsulation."""
        keypair = self._kem.generate_keypair()
        result = self._kem.encapsulate(keypair.public_key)
        return self._bench(
            "Decapsulation", "Kyber768", "KEM", iterations,
            lambda: self._kem.decapsulate(result.ciphertext, keypair.secret_key),
        )

    # --- Dilithium3 Benchmarks ---

    def bench_dilithium_keygen(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark Dilithium3 key generation."""
        signer = DilithiumSigner()
        return self._bench("Key Generation", "Dilithium3", "Signature", iterations, signer.generate_keypair)

    def bench_dilithium_sign(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark Dilithium3 signing."""
        signer = DilithiumSigner()
        keypair = signer.generate_keypair()
        message = b"QuantumShield benchmark test message for signing operations"
        return self._bench(
            "Sign", "Dilithium3", "Signature", iterations,
            lambda: signer.sign(message, keypair.secret_key),
        )

    def bench_dilithium_verify(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark Dilithium3 verification."""
        signer = DilithiumSigner()
        keypair = signer.generate_keypair()
        message = b"QuantumShield benchmark test message for signing operations"
        signature = signer.sign(message, keypair.secret_key)
        return self._bench(
            "Verify", "Dilithium3", "Signature", iterations,
            lambda: signer.verify(message, signature, keypair.public_key),
        )

    # --- Classical Crypto Benchmarks ---

    def bench_rsa2048_sign(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark RSA-2048 signing for comparison."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        message = b"QuantumShield benchmark test message for signing operations"
        return self._bench(
            "Sign", "RSA-2048", "Classical Signature", iterations,
            lambda: private_key.sign(message, padding.PKCS1v15(), hashes.SHA256()),
        )

    def bench_rsa2048_verify(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark RSA-2048 verification for comparison."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        message = b"QuantumShield benchmark test message for signing operations"
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return self._bench(
            "Verify", "RSA-2048", "Classical Signature", iterations,
            lambda: public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256()),
        )

    def bench_rsa2048_keygen(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark RSA-2048 key generation for comparison."""
        return self._bench(
            "Key Generation", "RSA-2048", "Classical Signature", iterations,
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        )

    def bench_x25519_keygen(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark X25519 key generation for comparison."""
        return self._bench(
            "Key Generation", "X25519 (ECDHE)", "Classical KEM", iterations,
            X25519PrivateKey.generate,
        )

    def bench_x25519_exchange(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark X25519 key exchange for comparison."""
        private_key = X25519PrivateKey.generate()
        peer_key = X25519PrivateKey.generate().public_key()
        return self._bench(
            "Key Exchange", "X25519 (ECDHE)", "Classical KEM", iterations,
            lambda: private_key.exchange(peer_key),
        )

    # --- Protocol Benchmarks ---

    def bench_kemtls_handshake(self, iterations: int = 10) -> BenchmarkResult:
        """Benchmark complete KEMTLS handshake."""
        return self._bench(
            "Full Handshake", "KEMTLS", "Protocol", iterations,
            perform_kemtls_handshake,
        )

    def bench_jwt_generation(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark JWT generation with Dilithium3 signing."""
        engine = TokenEngine()
        return self._bench(
            "JWT Generation", "Dilithium3", "Token", iterations,
            lambda: engine.create_id_token(sub="test-user", audience="test-client"),
        )

    def bench_jwt_verification(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark JWT verification with Dilithium3."""
        engine = TokenEngine()
        token = engine.create_id_token(sub="test-user", audience="test-client")
        return self._bench(
            "JWT Verification", "Dilithium3", "Token", iterations,
            lambda: engine.verify_jwt(token),
        )

    # --- Full Suite ---

    def run_full_suite(self, iterations: int = 100) -> BenchmarkSuite:
        """
        Run the complete benchmark suite.
        
        Args:
            iterations: Number of iterations for each benchmark.
            
        Returns:
            BenchmarkSuite with all results.
        """
        suite = BenchmarkSuite()
        suite_start = time.perf_counter()

        # Kyber768 benchmarks
        suite.results.append(self.bench_kyber_keygen(iterations))
        suite.results.append(self.bench_kyber_encapsulate(iterations))
        suite.results.append(self.bench_kyber_decapsulate(iterations))

        # Dilithium3 benchmarks
        suite.results.append(self.bench_dilithium_keygen(iterations))
        suite.results.append(self.bench_dilithium_sign(iterations))
        suite.results.append(self.bench_dilithium_verify(iterations))

        # Classical comparison benchmarks
        suite.results.append(self.bench_rsa2048_keygen(iterations))
        suite.results.append(self.bench_rsa2048_sign(iterations))
        suite.results.append(self.bench_rsa2048_verify(iterations))
        suite.results.append(self.bench_x25519_keygen(iterations))
        suite.results.append(self.bench_x25519_exchange(iterations))

        # Protocol benchmarks (fewer iterations)
        protocol_iters = max(1, iterations // 10)
        suite.results.append(self.bench_kemtls_handshake(protocol_iters))
        suite.results.append(self.bench_jwt_generation(iterations))
        suite.results.append(self.bench_jwt_verification(iterations))

        suite.total_duration_s = time.perf_counter() - suite_start
        return suite

    def run_quick_suite(self) -> BenchmarkSuite:
        """Run a quick benchmark with 10 iterations."""
        return self.run_full_suite(iterations=10)
