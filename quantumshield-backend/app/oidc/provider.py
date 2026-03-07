"""
OpenID Connect Provider

Implements OIDC Authorization Code Flow from scratch with PKCE support.
No external OAuth/OIDC libraries are used.
"""

import os
import time
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Optional

from app.oidc.pkce import PKCEVerifier


@dataclass
class OIDCClient:
    """Registered OIDC client."""
    client_id: str
    client_secret: str
    redirect_uris: list[str]
    client_name: str = ""
    allowed_scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])


@dataclass
class AuthorizationCode:
    """An issued authorization code."""
    code: str
    client_id: str
    redirect_uri: str
    scope: str
    user_id: str
    nonce: Optional[str] = None
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    issued_at: float = field(default_factory=time.time)
    expires_in: int = 600  # 10 minutes
    used: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() > self.issued_at + self.expires_in


@dataclass
class UserInfo:
    """User information for the userinfo endpoint."""
    sub: str  # Subject identifier
    name: str
    email: str
    email_verified: bool = True
    preferred_username: str = ""
    updated_at: int = field(default_factory=lambda: int(time.time()))


class OIDCProvider:
    """
    OpenID Connect Authorization Server.
    
    Implements the Authorization Code Flow with PKCE from scratch.
    All tokens are signed with Dilithium3 post-quantum signatures.
    """

    def __init__(self, issuer: str = "https://quantumshield.local") -> None:
        self.issuer = issuer
        self._clients: dict[str, OIDCClient] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._users: dict[str, UserInfo] = {}
        self._pkce = PKCEVerifier()
        self._setup_demo_data()

    def _setup_demo_data(self) -> None:
        """Set up demo users and clients for testing."""
        # Demo client
        demo_client = OIDCClient(
            client_id="quantumshield-demo-client",
            client_secret=secrets.token_urlsafe(32),
            redirect_uris=["http://localhost:3000/callback", "http://localhost:5173/callback"],
            client_name="QuantumShield Demo Application",
            allowed_scopes=["openid", "profile", "email"],
        )
        self._clients[demo_client.client_id] = demo_client

        # Demo users
        demo_users = [
            UserInfo(
                sub="user-001",
                name="Alice Quantum",
                email="alice@quantumshield.local",
                preferred_username="alice",
            ),
            UserInfo(
                sub="user-002",
                name="Bob Shield",
                email="bob@quantumshield.local",
                preferred_username="bob",
            ),
        ]
        for user in demo_users:
            self._users[user.sub] = user

    def register_client(
        self,
        client_name: str,
        redirect_uris: list[str],
        allowed_scopes: Optional[list[str]] = None,
    ) -> OIDCClient:
        """
        Register a new OIDC client.
        
        Args:
            client_name: Human-readable client name.
            redirect_uris: Allowed redirect URIs.
            allowed_scopes: Allowed scopes for this client.
            
        Returns:
            The registered OIDCClient.
        """
        client = OIDCClient(
            client_id=f"qs-{secrets.token_urlsafe(16)}",
            client_secret=secrets.token_urlsafe(32),
            redirect_uris=redirect_uris,
            client_name=client_name,
            allowed_scopes=allowed_scopes or ["openid", "profile", "email"],
        )
        self._clients[client.client_id] = client
        return client

    def validate_authorization_request(
        self,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        scope: str,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ) -> dict:
        """
        Validate an authorization request per OIDC spec.
        
        Returns:
            Dict with validation result and any errors.
        """
        errors = []

        # Validate client
        client = self._clients.get(client_id)
        if not client:
            errors.append("invalid_client: Client not registered")
            return {"valid": False, "errors": errors}

        # Validate redirect URI
        if redirect_uri not in client.redirect_uris:
            errors.append("invalid_redirect_uri: Redirect URI not registered")

        # Validate response type
        if response_type != "code":
            errors.append("unsupported_response_type: Only 'code' is supported")

        # Validate scope
        requested_scopes = scope.split()
        if "openid" not in requested_scopes:
            errors.append("invalid_scope: 'openid' scope is required")
        for s in requested_scopes:
            if s not in client.allowed_scopes:
                errors.append(f"invalid_scope: Scope '{s}' not allowed for this client")

        # Validate PKCE
        if code_challenge and code_challenge_method != "S256":
            errors.append("invalid_request: Only S256 code_challenge_method is supported")

        if errors:
            return {"valid": False, "errors": errors}

        return {
            "valid": True,
            "client": client,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }

    def issue_authorization_code(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        user_id: str,
        nonce: Optional[str] = None,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ) -> AuthorizationCode:
        """
        Issue an authorization code after user authentication.
        
        Args:
            client_id: The requesting client's ID.
            redirect_uri: The callback URI.
            scope: Requested scopes.
            user_id: Authenticated user's ID.
            nonce: OIDC nonce for replay protection.
            state: CSRF protection state parameter.
            code_challenge: PKCE code challenge.
            code_challenge_method: PKCE challenge method (S256).
            
        Returns:
            The issued AuthorizationCode.
        """
        code = secrets.token_urlsafe(32)
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            user_id=user_id,
            nonce=nonce,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        self._auth_codes[code] = auth_code
        return auth_code

    def validate_token_request(
        self,
        grant_type: str,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> dict:
        """
        Validate a token exchange request.
        
        Returns:
            Dict with validation result, user_id, and any errors.
        """
        errors = []

        if grant_type != "authorization_code":
            errors.append("unsupported_grant_type: Only 'authorization_code' is supported")
            return {"valid": False, "errors": errors}

        # Validate authorization code
        auth_code = self._auth_codes.get(code)
        if not auth_code:
            errors.append("invalid_grant: Authorization code not found")
            return {"valid": False, "errors": errors}

        if auth_code.used:
            errors.append("invalid_grant: Authorization code already used")
            return {"valid": False, "errors": errors}

        if auth_code.is_expired:
            errors.append("invalid_grant: Authorization code expired")
            return {"valid": False, "errors": errors}

        # Validate client
        if auth_code.client_id != client_id:
            errors.append("invalid_client: Client ID mismatch")

        client = self._clients.get(client_id)
        if client and client_secret and client.client_secret != client_secret:
            errors.append("invalid_client: Invalid client secret")

        # Validate redirect URI
        if auth_code.redirect_uri != redirect_uri:
            errors.append("invalid_grant: Redirect URI mismatch")

        # Validate PKCE
        if auth_code.code_challenge:
            if not code_verifier:
                errors.append("invalid_grant: code_verifier required for PKCE")
            elif not self._pkce.verify_challenge(
                code_verifier,
                auth_code.code_challenge,
                auth_code.code_challenge_method or "S256",
            ):
                errors.append("invalid_grant: PKCE verification failed")

        if errors:
            return {"valid": False, "errors": errors}

        # Mark code as used
        auth_code.used = True

        return {
            "valid": True,
            "user_id": auth_code.user_id,
            "scope": auth_code.scope,
            "nonce": auth_code.nonce,
            "client_id": client_id,
        }

    def get_user_info(self, user_id: str) -> Optional[UserInfo]:
        """Get user information by user ID."""
        return self._users.get(user_id)

    def get_client(self, client_id: str) -> Optional[OIDCClient]:
        """Get client by client ID."""
        return self._clients.get(client_id)

    def get_openid_configuration(self) -> dict:
        """
        Generate the OpenID Provider Configuration document.
        Per OpenID Connect Discovery 1.0.
        """
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/jwks.json",
            "registration_endpoint": f"{self.issuer}/register",
            "scopes_supported": ["openid", "profile", "email"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["DILITHIUM3"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": ["sub", "name", "email", "email_verified", "preferred_username", "iss", "aud", "exp", "iat", "nonce"],
            "quantum_resistant": True,
            "kem_algorithm": "Kyber768",
            "signature_algorithm": "Dilithium3",
            "transport_protocol": "KEMTLS",
        }

    def list_clients(self) -> list[dict]:
        """List all registered clients (without secrets)."""
        return [
            {
                "client_id": c.client_id,
                "client_name": c.client_name,
                "redirect_uris": c.redirect_uris,
                "allowed_scopes": c.allowed_scopes,
            }
            for c in self._clients.values()
        ]

    def list_users(self) -> list[dict]:
        """List all users."""
        return [
            {
                "sub": u.sub,
                "name": u.name,
                "email": u.email,
                "preferred_username": u.preferred_username,
            }
            for u in self._users.values()
        ]
