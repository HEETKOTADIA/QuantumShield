# QuantumShield Architecture

## System Overview

QuantumShield is a modular post-quantum secure identity platform consisting of seven core modules communicating through a FastAPI application layer. The system demonstrates end-to-end post-quantum security from transport layer (KEMTLS) through application layer (OIDC with PQ-signed tokens).

## Module Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (React/TypeScript)            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │  Status   │ │  KEMTLS  │ │   Auth   │ │Benchmarks│   │
│  │Dashboard  │ │ Monitor  │ │   Flow   │ │  Charts  │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│  ┌──────────┐                                            │
│  │ Quantum  │                                            │
│  │ Scanner  │                                            │
│  └──────────┘                                            │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP / JSON
┌──────────────────────┴──────────────────────────────────┐
│                  API Layer (FastAPI)                      │
│  ┌────────────────────────────────────────────────────┐  │
│  │  /api/status  /api/kemtls  /authorize  /token      │  │
│  │  /userinfo  /jwks.json  /api/benchmarks            │  │
│  │  /api/scanner  /api/crypto                         │  │
│  └────────────────────────────────────────────────────┘  │
└──┬────────┬────────┬────────┬────────┬────────┬─────────┘
   │        │        │        │        │        │
┌──┴──┐ ┌──┴──┐ ┌──┴──┐ ┌──┴──┐ ┌──┴──┐ ┌──┴──┐
│  PQ  │ │KEMTLS│ │OIDC │ │Token│ │Bench│ │Scan │
│Crypto│ │Engine│ │Prov.│ │Eng. │ │mark │ │ner  │
└──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └─────┘
   │        │        │        │        │
┌──┴────────┴────────┴────────┴────────┴──┐
│          liboqs (Open Quantum Safe)      │
│    Kyber768 (ML-KEM)  Dilithium3 (ML-DSA) │
└─────────────────────────────────────────┘
```

## Module Descriptions

### 1. PQ Crypto Module (`app/pqcrypto/`)

**Purpose**: Provides post-quantum cryptographic primitives via liboqs-python.

**Components**:
- `kem.py` — KyberKEM class: key generation, encapsulation, decapsulation
- `signatures.py` — DilithiumSigner class: key generation, signing, verification

**Algorithms**:
- Kyber768 (ML-KEM-768, NIST Level 3): 1184-byte public key, 1088-byte ciphertext, 32-byte shared secret
- Dilithium3 (ML-DSA-65, NIST Level 3): 1952-byte public key, 3309-byte signature

### 2. KEMTLS Protocol Engine (`app/kemtls/`)

**Purpose**: Implements KEM-based TLS handshake above TCP for research purposes.

**Components**:
- `protocol.py` — KEMTLSServer, KEMTLSClient: handshake state machines
- `channel.py` — SecureChannel: AES-256-GCM encrypted communication

**Handshake Flow**:
1. ClientHello → Server (supported algorithms)
2. ServerHello → Client (Kyber768 public key + Dilithium3 signing key)
3. ClientKEMEncap → Server (KEM ciphertext containing shared secret)
4. ServerKEMDecap (internal: decapsulate shared secret)
5. ServerAuth → Client (Dilithium3 signature over transcript hash)
6. ClientVerify (internal: verify signature, establish channel)

**Key Derivation**: HKDF-SHA256 from KEM shared secret → 256-bit AES key

### 3. OIDC Provider (`app/oidc/`)

**Purpose**: Full OpenID Connect Authorization Code Flow implementation from scratch.

**Components**:
- `provider.py` — OIDCProvider: authorization, token validation, client management
- `pkce.py` — PKCEVerifier: S256 code challenge generation and verification

**Features**:
- Client registration with redirect URI validation
- Authorization codes with configurable expiry (10 min default)
- PKCE S256 challenge/verifier validation
- Nonce, state, scope validation
- OpenID Provider Configuration document

### 4. Token Engine (`app/tokens/`)

**Purpose**: JWT/JWS creation and verification with Dilithium3 signatures.

**Components**:
- `engine.py` — TokenEngine: JWT creation, verification, refresh token rotation
- `jwks.py` — JWKSProvider: Publishes Dilithium3 public key in JWKS format

**Token Types**:
- ID Token (OIDC identity claims)
- Access Token (authorization scope)
- Refresh Token (with rotation support)

**Format**: Standard `header.payload.signature` with `alg: DILITHIUM3`

### 5. Benchmarking System (`app/benchmarking/`)

**Purpose**: Performance measurement of PQ and classical cryptographic operations.

**Components**:
- `engine.py` — BenchmarkEngine: individual and suite benchmarks
- `report.py` — ReportGenerator: PDF reports with charts

**Operations Benchmarked**:
- Kyber768: keygen, encapsulate, decapsulate
- Dilithium3: keygen, sign, verify
- RSA-2048: keygen, sign, verify (comparison)
- X25519: keygen, key exchange (comparison)
- KEMTLS: full handshake latency
- JWT: generation and verification

**Statistics**: mean, median, min, max, stddev (all via `time.perf_counter()`)

### 6. Quantum Readiness Scanner (`app/scanner/`)

**Purpose**: Assesses quantum vulnerability of external TLS configurations.

**Components**:
- `tls_scanner.py` — QuantumReadinessScanner: TLS inspection and classification

**Process**:
1. Open TLS connection to target domain
2. Inspect certificate (subject, issuer, algorithm, key type/size)
3. Inspect cipher suite
4. Classify algorithms (quantum_vulnerable / quantum_resistant / hybrid)
5. Generate vulnerability notes and recommendations

### 7. Frontend Dashboard (`quantumshield-frontend/`)

**Purpose**: Professional security monitoring interface.

**Pages**:
- System Status: Crypto configuration overview
- KEMTLS Monitor: Interactive handshake visualization with step animation
- Authentication Flow: OIDC demo with PKCE, token verification display
- Benchmarks: PQ vs classical comparison charts and tables
- Quantum Scanner: Domain scanning with detailed results panel

**Technology**: React + TypeScript + Tailwind CSS + Recharts

## Data Flow: Complete Authentication

```
1. User clicks "Login" → Client generates PKCE (code_verifier, code_challenge)
2. Client → POST /authorize (client_id, redirect_uri, scope, code_challenge, nonce, state)
3. Server validates request, issues authorization_code
4. Client → POST /token (code, code_verifier, redirect_uri)
5. Server validates code, verifies PKCE, issues:
   - ID Token (Dilithium3 signed JWT with identity claims)
   - Access Token (Dilithium3 signed JWT with scope)
   - Refresh Token (Dilithium3 signed JWT, rotatable)
6. All token exchange is secured over KEMTLS channel (AES-256-GCM)
7. Client verifies tokens via /jwks.json (Dilithium3 public key)
```

## Security Properties

| Property | Implementation |
|----------|---------------|
| Quantum-resistant key exchange | Kyber768 (ML-KEM-768) |
| Quantum-resistant signatures | Dilithium3 (ML-DSA-65) |
| Forward secrecy | Fresh KEM keypairs per session |
| Authenticated encryption | AES-256-GCM |
| CSRF protection | State parameter |
| Replay protection | Nonce parameter |
| Code interception protection | PKCE S256 |
| Token integrity | Dilithium3 JWT signatures |
