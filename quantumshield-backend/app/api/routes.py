"""
QuantumShield API Routes

FastAPI routers for all QuantumShield endpoints including OIDC, KEMTLS,
benchmarking, and quantum scanner.
"""

import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from app.pqcrypto.kem import KyberKEM
from app.pqcrypto.signatures import DilithiumSigner
from app.kemtls.protocol import KEMTLSServer, KEMTLSClient, perform_kemtls_handshake, KEMTLSSession
from app.kemtls.channel import SecureChannel
from app.oidc.provider import OIDCProvider
from app.oidc.pkce import PKCEVerifier
from app.tokens.engine import TokenEngine
from app.tokens.jwks import JWKSProvider
from app.benchmarking.engine import BenchmarkEngine
from app.benchmarking.report import ReportGenerator
from app.scanner.tls_scanner import QuantumReadinessScanner


# ============================================================
# Shared state (singleton instances)
# ============================================================
_oidc_provider = OIDCProvider(issuer="https://quantumshield.local")
_token_engine = TokenEngine(issuer="https://quantumshield.local")
_jwks_provider = JWKSProvider(_token_engine.public_key)
_benchmark_engine = BenchmarkEngine()
_report_generator = ReportGenerator()
_scanner = QuantumReadinessScanner()
_last_benchmark_suite = None
_kemtls_sessions: dict[str, dict] = {}

# ============================================================
# Routers
# ============================================================
status_router = APIRouter(prefix="/api/status", tags=["Status"])
kemtls_router = APIRouter(prefix="/api/kemtls", tags=["KEMTLS"])
oidc_router = APIRouter(tags=["OIDC"])
benchmark_router = APIRouter(prefix="/api/benchmarks", tags=["Benchmarks"])
scanner_router = APIRouter(prefix="/api/scanner", tags=["Scanner"])
crypto_router = APIRouter(prefix="/api/crypto", tags=["Crypto"])


# ============================================================
# Pydantic Models
# ============================================================
class AuthorizeRequest(BaseModel):
    client_id: str
    redirect_uri: str
    response_type: str = "code"
    scope: str = "openid profile email"
    state: Optional[str] = None
    nonce: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    user_id: str = "user-001"


class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: str = ""
    client_secret: Optional[str] = None
    code_verifier: Optional[str] = None
    refresh_token: Optional[str] = None


class ClientRegisterRequest(BaseModel):
    client_name: str
    redirect_uris: list[str]
    allowed_scopes: Optional[list[str]] = None


class ScanRequest(BaseModel):
    domains: list[str]
    port: int = 443


class KEMTLSHandshakeRequest(BaseModel):
    """Request to initiate a KEMTLS handshake demonstration."""
    pass


class VerifyTokenRequest(BaseModel):
    token: str


# ============================================================
# Status Endpoints
# ============================================================
@status_router.get("")
async def get_system_status():
    """Get comprehensive system status."""
    kyber_details = KyberKEM.get_algorithm_details()
    dilithium_details = DilithiumSigner.get_algorithm_details()

    return {
        "system": "QuantumShield",
        "version": "1.0.0",
        "status": "operational",
        "transport_protocol": "KEMTLS",
        "quantum_resistance": "enabled",
        "oidc_compliance": "active",
        "crypto_config": {
            "kem_algorithm": kyber_details,
            "signature_algorithm": dilithium_details,
            "symmetric_cipher": "AES-256-GCM",
            "kdf": "HKDF-SHA256",
        },
        "endpoints": {
            "oidc_discovery": "/.well-known/openid-configuration",
            "authorize": "/authorize",
            "token": "/token",
            "userinfo": "/userinfo",
            "jwks": "/jwks.json",
        },
        "uptime_since": time.time(),
    }


# ============================================================
# KEMTLS Endpoints
# ============================================================
@kemtls_router.post("/handshake")
async def perform_handshake():
    """
    Perform a complete KEMTLS handshake demonstration.
    Returns detailed handshake log with timing information.
    """
    try:
        server_session, client_session = perform_kemtls_handshake()

        # Test the secure channel
        channel_server = SecureChannel(server_session.session_key)
        channel_client = SecureChannel(client_session.session_key)

        test_message = b"QuantumShield KEMTLS secure channel test"
        encrypted = channel_server.encrypt(test_message)
        decrypted = channel_client.decrypt(encrypted)

        # Store session info
        _kemtls_sessions[server_session.session_id] = server_session.to_dict()

        return {
            "status": "success",
            "server_session": server_session.to_dict(),
            "client_session": client_session.to_dict(),
            "channel_test": {
                "plaintext_size": len(test_message),
                "ciphertext_size": encrypted.total_size(),
                "decryption_verified": decrypted == test_message,
                "cipher_suite": "AES-256-GCM",
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Handshake failed: {str(e)}")


@kemtls_router.get("/sessions")
async def list_sessions():
    """List recent KEMTLS sessions."""
    return {"sessions": list(_kemtls_sessions.values())[-10:]}


@kemtls_router.post("/encrypt-test")
async def encrypt_test():
    """Test AES-256-GCM encryption over KEMTLS channel."""
    server_session, client_session = perform_kemtls_handshake()
    channel = SecureChannel(server_session.session_key)

    messages = [
        b"OIDC Authorization Request",
        b"Access Token: eyJhbGciOiJESUxJVEhJVU0zIn0...",
        b"UserInfo Response: {\"sub\": \"user-001\"}",
    ]

    results = []
    for msg in messages:
        encrypted = channel.encrypt(msg, b"kemtls-oidc")
        decrypted = SecureChannel(client_session.session_key).decrypt(encrypted)
        results.append({
            "plaintext_size": len(msg),
            "ciphertext_size": len(encrypted.ciphertext),
            "nonce_size": len(encrypted.nonce),
            "verified": decrypted == msg,
        })

    return {
        "cipher_suite": "AES-256-GCM",
        "key_size_bits": 256,
        "messages_tested": len(results),
        "results": results,
        "handshake_latency_ms": server_session.handshake_log.total_latency_ms,
    }


# ============================================================
# OIDC Endpoints
# ============================================================
@oidc_router.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OpenID Provider Configuration endpoint."""
    return _oidc_provider.get_openid_configuration()


@oidc_router.get("/jwks.json")
async def jwks():
    """JWKS endpoint publishing Dilithium3 public key."""
    return _jwks_provider.get_jwks()


@oidc_router.post("/authorize")
async def authorize(request: AuthorizeRequest):
    """
    Authorization endpoint.
    Validates the request and issues an authorization code.
    """
    validation = _oidc_provider.validate_authorization_request(
        client_id=request.client_id,
        redirect_uri=request.redirect_uri,
        response_type=request.response_type,
        scope=request.scope,
        state=request.state,
        nonce=request.nonce,
        code_challenge=request.code_challenge,
        code_challenge_method=request.code_challenge_method,
    )

    if not validation["valid"]:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "errors": validation["errors"]})

    auth_code = _oidc_provider.issue_authorization_code(
        client_id=request.client_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        user_id=request.user_id,
        nonce=request.nonce,
        state=request.state,
        code_challenge=request.code_challenge,
        code_challenge_method=request.code_challenge_method,
    )

    return {
        "code": auth_code.code,
        "state": request.state,
        "redirect_uri": f"{request.redirect_uri}?code={auth_code.code}&state={request.state}",
    }


@oidc_router.post("/token")
async def token(request: TokenRequest):
    """
    Token endpoint.
    Exchanges authorization code for tokens, or refreshes tokens.
    """
    if request.grant_type == "authorization_code":
        if not request.code or not request.redirect_uri:
            raise HTTPException(status_code=400, detail={"error": "invalid_request", "description": "code and redirect_uri required"})

        validation = _oidc_provider.validate_token_request(
            grant_type=request.grant_type,
            code=request.code,
            redirect_uri=request.redirect_uri,
            client_id=request.client_id,
            client_secret=request.client_secret,
            code_verifier=request.code_verifier,
        )

        if not validation["valid"]:
            raise HTTPException(status_code=400, detail={"error": "invalid_grant", "errors": validation["errors"]})

        user = _oidc_provider.get_user_info(validation["user_id"])
        token_set = _token_engine.issue_token_set(
            sub=validation["user_id"],
            scope=validation["scope"],
            client_id=validation["client_id"],
            nonce=validation.get("nonce"),
            name=user.name if user else None,
            email=user.email if user else None,
        )

        return token_set.to_dict()

    elif request.grant_type == "refresh_token":
        if not request.refresh_token:
            raise HTTPException(status_code=400, detail={"error": "invalid_request", "description": "refresh_token required"})

        validation = _token_engine.validate_refresh_token(request.refresh_token)
        if not validation["valid"]:
            raise HTTPException(status_code=400, detail={"error": "invalid_grant", "description": validation.get("error", "Invalid refresh token")})

        # Issue new access token
        new_access = _token_engine.create_access_token(
            sub=validation["sub"],
            scope=validation["scope"],
            audience=validation["client_id"],
        )

        # Rotate refresh token
        new_refresh = _token_engine.rotate_refresh_token(
            old_refresh_token=request.refresh_token,
            sub=validation["sub"],
            scope=validation["scope"],
            client_id=validation["client_id"],
        )

        return {
            "access_token": new_access,
            "refresh_token": new_refresh,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": validation["scope"],
        }

    else:
        raise HTTPException(status_code=400, detail={"error": "unsupported_grant_type"})


@oidc_router.get("/userinfo")
async def userinfo(sub: str = Query(..., description="User subject identifier")):
    """UserInfo endpoint."""
    user = _oidc_provider.get_user_info(sub)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "sub": user.sub,
        "name": user.name,
        "email": user.email,
        "email_verified": user.email_verified,
        "preferred_username": user.preferred_username,
        "updated_at": user.updated_at,
    }


@oidc_router.post("/register")
async def register_client(request: ClientRegisterRequest):
    """Dynamic client registration endpoint."""
    client = _oidc_provider.register_client(
        client_name=request.client_name,
        redirect_uris=request.redirect_uris,
        allowed_scopes=request.allowed_scopes,
    )
    return {
        "client_id": client.client_id,
        "client_secret": client.client_secret,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
    }


@oidc_router.get("/api/oidc/clients")
async def list_clients():
    """List registered OIDC clients."""
    return {"clients": _oidc_provider.list_clients()}


@oidc_router.get("/api/oidc/users")
async def list_users():
    """List users."""
    return {"users": _oidc_provider.list_users()}


@oidc_router.post("/api/oidc/verify-token")
async def verify_token(request: VerifyTokenRequest):
    """Verify a JWT token."""
    result = _token_engine.verify_jwt(request.token)
    return result


@oidc_router.post("/api/oidc/demo-flow")
async def demo_oidc_flow():
    """
    Execute a complete OIDC authorization code flow demonstration.
    Simulates all steps: authorization → token exchange → userinfo.
    """
    # Step 1: Generate PKCE
    pkce = PKCEVerifier()
    code_verifier = pkce.generate_code_verifier()
    code_challenge = pkce.generate_code_challenge(code_verifier)

    # Step 2: Authorization request
    client = _oidc_provider.get_client("quantumshield-demo-client")
    if not client:
        raise HTTPException(status_code=500, detail="Demo client not configured")

    auth_code = _oidc_provider.issue_authorization_code(
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
        scope="openid profile email",
        user_id="user-001",
        nonce="demo-nonce-" + str(int(time.time())),
        state="demo-state-" + str(int(time.time())),
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    # Step 3: Token exchange with PKCE verification
    validation = _oidc_provider.validate_token_request(
        grant_type="authorization_code",
        code=auth_code.code,
        redirect_uri=client.redirect_uris[0],
        client_id=client.client_id,
        client_secret=client.client_secret,
        code_verifier=code_verifier,
    )

    if not validation["valid"]:
        raise HTTPException(status_code=500, detail=f"Token validation failed: {validation['errors']}")

    user = _oidc_provider.get_user_info(validation["user_id"])
    token_set = _token_engine.issue_token_set(
        sub=validation["user_id"],
        scope=validation["scope"],
        client_id=validation["client_id"],
        nonce=validation.get("nonce"),
        name=user.name if user else None,
        email=user.email if user else None,
    )

    # Step 4: Verify tokens
    id_verification = _token_engine.verify_jwt(token_set.id_token)
    access_verification = _token_engine.verify_jwt(token_set.access_token)

    return {
        "flow": "Authorization Code with PKCE",
        "steps": [
            {
                "step": 1,
                "name": "PKCE Generation",
                "code_challenge_method": "S256",
                "code_verifier_length": len(code_verifier),
                "code_challenge": code_challenge,
            },
            {
                "step": 2,
                "name": "Authorization Request",
                "authorization_code": auth_code.code[:16] + "...",
                "scope": "openid profile email",
                "state": auth_code.state,
                "nonce": auth_code.nonce,
            },
            {
                "step": 3,
                "name": "Token Exchange",
                "pkce_verified": True,
                "tokens_issued": {
                    "id_token": token_set.id_token[:50] + "...",
                    "access_token": token_set.access_token[:50] + "...",
                    "refresh_token": token_set.refresh_token[:50] + "...",
                },
                "signature_algorithm": "Dilithium3",
            },
            {
                "step": 4,
                "name": "Token Verification",
                "id_token_valid": id_verification["valid"],
                "access_token_valid": access_verification["valid"],
                "id_token_claims": id_verification.get("payload", {}),
            },
        ],
        "user": {
            "sub": user.sub if user else "",
            "name": user.name if user else "",
            "email": user.email if user else "",
        },
        "security": {
            "signature_algorithm": "Dilithium3 (ML-DSA-65)",
            "quantum_resistant": True,
            "pkce_method": "S256",
        },
    }


# ============================================================
# Benchmark Endpoints
# ============================================================
@benchmark_router.post("/run")
async def run_benchmarks(iterations: int = Query(default=100, ge=1, le=1000)):
    """Run the full benchmark suite."""
    global _last_benchmark_suite
    suite = _benchmark_engine.run_full_suite(iterations=iterations)
    _last_benchmark_suite = suite
    return suite.to_dict()


@benchmark_router.post("/quick")
async def run_quick_benchmarks():
    """Run a quick benchmark with 10 iterations."""
    global _last_benchmark_suite
    suite = _benchmark_engine.run_quick_suite()
    _last_benchmark_suite = suite
    return suite.to_dict()


@benchmark_router.get("/results")
async def get_benchmark_results():
    """Get the latest benchmark results."""
    if _last_benchmark_suite is None:
        raise HTTPException(status_code=404, detail="No benchmarks have been run yet")
    return _last_benchmark_suite.to_dict()


@benchmark_router.post("/report")
async def generate_benchmark_report():
    """Generate and return the BenchmarkResults.pdf."""
    global _last_benchmark_suite
    if _last_benchmark_suite is None:
        _last_benchmark_suite = _benchmark_engine.run_quick_suite()
    path = _report_generator.generate_benchmark_report(_last_benchmark_suite)
    return FileResponse(path, media_type="application/pdf", filename="BenchmarkResults.pdf")


@benchmark_router.post("/technical-docs")
async def generate_technical_docs():
    """Generate and return the TechnicalDocumentation.pdf."""
    path = _report_generator.generate_technical_documentation()
    return FileResponse(path, media_type="application/pdf", filename="TechnicalDocumentation.pdf")


# ============================================================
# Scanner Endpoints
# ============================================================
@scanner_router.post("/scan")
async def scan_domains(request: ScanRequest):
    """Scan domains for quantum readiness."""
    results = _scanner.scan_multiple(request.domains, request.port)
    return {
        "scan_count": len(results),
        "results": [r.to_dict() for r in results],
        "summary": {
            "vulnerable": sum(1 for r in results if r.quantum_readiness.value == "quantum_vulnerable"),
            "resistant": sum(1 for r in results if r.quantum_readiness.value == "quantum_resistant"),
            "hybrid": sum(1 for r in results if r.quantum_readiness.value == "hybrid"),
            "unknown": sum(1 for r in results if r.quantum_readiness.value == "unknown"),
            "errors": sum(1 for r in results if r.error is not None),
        },
    }


@scanner_router.post("/scan-single")
async def scan_single_domain(domain: str = Query(...), port: int = Query(default=443)):
    """Scan a single domain for quantum readiness."""
    result = _scanner.scan_domain(domain, port)
    return result.to_dict()


# ============================================================
# Crypto Info Endpoints
# ============================================================
@crypto_router.get("/algorithms")
async def get_algorithm_info():
    """Get information about the PQ algorithms used."""
    return {
        "kem": KyberKEM.get_algorithm_details(),
        "signature": DilithiumSigner.get_algorithm_details(),
        "symmetric": {
            "name": "AES-256-GCM",
            "key_size_bits": 256,
            "nonce_size_bits": 96,
            "tag_size_bits": 128,
        },
        "kdf": {
            "name": "HKDF-SHA256",
            "output_length": 32,
        },
    }


@crypto_router.post("/demo-kem")
async def demo_kem():
    """Demonstrate Kyber768 KEM operations."""
    import time as t
    kem = KyberKEM()

    start = t.perf_counter()
    keypair = kem.generate_keypair()
    keygen_ms = (t.perf_counter() - start) * 1000

    start = t.perf_counter()
    result = kem.encapsulate(keypair.public_key)
    encap_ms = (t.perf_counter() - start) * 1000

    start = t.perf_counter()
    shared_secret = kem.decapsulate(result.ciphertext, keypair.secret_key)
    decap_ms = (t.perf_counter() - start) * 1000

    return {
        "algorithm": "Kyber768",
        "public_key_size": len(keypair.public_key),
        "secret_key_size": len(keypair.secret_key),
        "ciphertext_size": len(result.ciphertext),
        "shared_secret_size": len(result.shared_secret),
        "secrets_match": shared_secret == result.shared_secret,
        "timing_ms": {
            "keygen": round(keygen_ms, 4),
            "encapsulate": round(encap_ms, 4),
            "decapsulate": round(decap_ms, 4),
        },
    }


@crypto_router.post("/demo-signature")
async def demo_signature():
    """Demonstrate Dilithium3 signature operations."""
    import time as t
    signer = DilithiumSigner()

    start = t.perf_counter()
    keypair = signer.generate_keypair()
    keygen_ms = (t.perf_counter() - start) * 1000

    message = b"QuantumShield: Post-Quantum Secure OpenID Connect"

    start = t.perf_counter()
    signature = signer.sign(message, keypair.secret_key)
    sign_ms = (t.perf_counter() - start) * 1000

    start = t.perf_counter()
    is_valid = signer.verify(message, signature, keypair.public_key)
    verify_ms = (t.perf_counter() - start) * 1000

    return {
        "algorithm": "Dilithium3",
        "public_key_size": len(keypair.public_key),
        "secret_key_size": len(keypair.secret_key),
        "signature_size": len(signature),
        "message_size": len(message),
        "signature_valid": is_valid,
        "timing_ms": {
            "keygen": round(keygen_ms, 4),
            "sign": round(sign_ms, 4),
            "verify": round(verify_ms, 4),
        },
    }
