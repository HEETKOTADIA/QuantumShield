# QuantumShield

**Post-Quantum Secure OpenID Connect using KEMTLS**

A research-grade prototype implementing a fully functional OpenID Connect identity provider secured using Post-Quantum Cryptography and a KEMTLS transport layer.

## Overview

QuantumShield demonstrates the feasibility of post-quantum secure identity infrastructure by combining:

- **KEMTLS**: KEM-based TLS handshake using Kyber768 (ML-KEM-768) for key encapsulation
- **Post-Quantum Signatures**: Dilithium3 (ML-DSA-65) for JWT signing and server authentication
- **OIDC from Scratch**: Full Authorization Code Flow with PKCE, implemented without OAuth/OIDC frameworks
- **Real PQ Cryptography**: All operations use liboqs (Open Quantum Safe) — no simulated randomness

## Cryptographic Algorithms

| Component | Algorithm | NIST Level | Standard |
|-----------|-----------|-----------|----------|
| Key Encapsulation | Kyber768 | Level 3 | ML-KEM-768 (FIPS 203) |
| Digital Signatures | Dilithium3 | Level 3 | ML-DSA-65 (FIPS 204) |
| Symmetric Encryption | AES-256-GCM | — | NIST SP 800-38D |
| Key Derivation | HKDF-SHA256 | — | RFC 5869 |

## Architecture

```
quantumshield/
├── quantumshield-backend/          # FastAPI backend
│   └── app/
│       ├── pqcrypto/               # Kyber768 KEM + Dilithium3 signatures (liboqs)
│       ├── kemtls/                 # KEMTLS protocol engine + AES-256-GCM channel
│       ├── oidc/                   # OIDC Authorization Code Flow + PKCE
│       ├── tokens/                 # JWT engine with Dilithium3 signing + JWKS
│       ├── benchmarking/           # PQ vs classical performance benchmarks
│       ├── scanner/                # Quantum readiness TLS scanner
│       └── api/                    # FastAPI routes
├── quantumshield-frontend/         # React + TypeScript dashboard
│   └── src/
│       └── components/
│           ├── StatusPage.tsx       # System status & crypto config
│           ├── KEMTLSPage.tsx       # KEMTLS handshake monitor
│           ├── AuthPage.tsx         # OIDC authentication flow
│           ├── BenchmarksPage.tsx   # Benchmark results & charts
│           └── ScannerPage.tsx      # Quantum readiness scanner
└── docs/
    ├── Architecture.md
    ├── TechnicalDocumentation.pdf
    └── BenchmarkResults.pdf
```

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 18+
- liboqs (Open Quantum Safe) shared library

### Install liboqs

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install && sudo ldconfig
```

### Backend

```bash
cd quantumshield-backend
poetry install
poetry run fastapi dev app/main.py --port 8000
```

### Frontend

```bash
cd quantumshield-frontend
npm install
npm run dev
```

Open http://localhost:5173 to access the dashboard.

## API Endpoints

### OIDC Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OpenID Provider Configuration |
| `POST /authorize` | Authorization endpoint |
| `POST /token` | Token endpoint (auth code + refresh) |
| `GET /userinfo` | UserInfo endpoint |
| `GET /jwks.json` | JWKS with Dilithium3 public key |
| `POST /register` | Dynamic client registration |

### KEMTLS Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/kemtls/handshake` | Perform KEMTLS handshake |
| `GET /api/kemtls/sessions` | List KEMTLS sessions |
| `POST /api/kemtls/encrypt-test` | Test AES-256-GCM channel |

### Benchmark Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/benchmarks/run?iterations=N` | Run full benchmark suite |
| `POST /api/benchmarks/quick` | Quick benchmark (10 iterations) |
| `POST /api/benchmarks/report` | Generate BenchmarkResults.pdf |
| `POST /api/benchmarks/technical-docs` | Generate TechnicalDocumentation.pdf |

### Scanner Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/scanner/scan` | Scan domains for quantum readiness |

## KEMTLS Handshake Flow

```
Client                              Server
  |                                    |
  |──── ClientHello ──────────────────>|  Supported algorithms
  |                                    |
  |<──── ServerHello ─────────────────|  Kyber768 public key + Dilithium3 key
  |                                    |
  |──── ClientKEMEncap ──────────────>|  Encapsulated shared secret
  |                                    |
  |      ServerKEMDecap               |  Server decapsulates shared secret
  |                                    |
  |<──── ServerAuth ──────────────────|  Dilithium3 signed transcript
  |                                    |
  |      ClientVerify                  |  Verify signature
  |                                    |
  |<═══ AES-256-GCM Secure Channel ═══>|  HKDF-derived session key
```

## OIDC Flow

The system implements the full Authorization Code Flow with PKCE:

1. **PKCE Generation**: Client generates code_verifier and code_challenge (S256)
2. **Authorization Request**: Client requests authorization with scope, state, nonce
3. **Token Exchange**: Authorization code exchanged for tokens with PKCE verification
4. **Token Verification**: All tokens signed and verified with Dilithium3

## Benchmarking

The system benchmarks both post-quantum and classical operations:

- **Kyber768**: Key generation, encapsulation, decapsulation
- **Dilithium3**: Key generation, signing, verification
- **RSA-2048**: Key generation, signing, verification (comparison)
- **X25519**: Key generation, key exchange (comparison)
- **KEMTLS**: Full handshake latency
- **JWT**: Generation and verification with Dilithium3

All timing uses `time.perf_counter()` with configurable iterations (10/100/1000).

## Quantum Readiness Scanner

Scans external domains' TLS configurations and classifies algorithms:

| Classification | Algorithms |
|---------------|------------|
| Quantum Vulnerable | RSA, ECDSA, ECDHE, DHE |
| Quantum Resistant | ML-KEM, Dilithium, FALCON, SPHINCS+ |

## Security Notes

This is a **research prototype** for demonstrating post-quantum secure identity infrastructure. It is not intended for production use. Key limitations:

- KEMTLS operates above TCP as an application-layer protocol
- No X.509 PQ certificate chain
- Simplified key management (no HSM)
- Side-channel resistance not evaluated

## License

Research prototype — for educational and evaluation purposes.
