"""
Post-Quantum Token Engine

Implements JWT/JWS token creation and verification using Dilithium3 signatures.
Follows RFC 7519 (JWT) and RFC 7515 (JWS) manually without external JWT signing libraries.
"""

import json
import time
import base64
import secrets
from dataclasses import dataclass, field
from typing import Optional

from app.pqcrypto.signatures import DilithiumSigner, DilithiumKeyPair


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


@dataclass
class TokenSet:
    """A complete set of OIDC tokens."""
    id_token: str
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    scope: str = "openid profile email"

    def to_dict(self) -> dict:
        return {
            "id_token": self.id_token,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
        }


class TokenEngine:
    """
    JWT Token Engine with Dilithium3 Post-Quantum Signatures.
    
    Creates and verifies JWTs using the Dilithium3 digital signature scheme.
    All tokens follow the standard header.payload.signature format.
    """

    def __init__(self, issuer: str = "https://quantumshield.local") -> None:
        self.issuer = issuer
        self._signer = DilithiumSigner()
        self._keypair: Optional[DilithiumKeyPair] = None
        self._refresh_tokens: dict[str, dict] = {}
        self._initialize_keys()

    def _initialize_keys(self) -> None:
        """Generate Dilithium3 signing keys."""
        self._keypair = self._signer.generate_keypair()

    @property
    def public_key(self) -> bytes:
        """Get the Dilithium3 public key."""
        assert self._keypair is not None
        return self._keypair.public_key

    @property
    def secret_key(self) -> bytes:
        """Get the Dilithium3 secret key."""
        assert self._keypair is not None
        return self._keypair.secret_key

    def _create_jwt(self, payload: dict) -> str:
        """
        Create a JWT signed with Dilithium3.
        
        Format: base64url(header).base64url(payload).base64url(signature)
        """
        assert self._keypair is not None

        header = {
            "alg": "DILITHIUM3",
            "typ": "JWT",
            "kid": "quantumshield-dilithium3-key-1",
        }

        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = self._signer.sign(signing_input, self._keypair.secret_key)
        signature_b64 = _b64url_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def verify_jwt(self, token: str) -> dict:
        """
        Verify a JWT signed with Dilithium3.
        
        Args:
            token: The JWT string.
            
        Returns:
            Dict with verification result and decoded payload.
        """
        assert self._keypair is not None

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"valid": False, "error": "Invalid JWT format"}

            header_b64, payload_b64, signature_b64 = parts

            # Decode header
            header = json.loads(_b64url_decode(header_b64))
            if header.get("alg") != "DILITHIUM3":
                return {"valid": False, "error": f"Unsupported algorithm: {header.get('alg')}"}

            # Verify signature
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            signature = _b64url_decode(signature_b64)
            is_valid = self._signer.verify(signing_input, signature, self._keypair.public_key)

            if not is_valid:
                return {"valid": False, "error": "Signature verification failed"}

            # Decode payload
            payload = json.loads(_b64url_decode(payload_b64))

            # Check expiration
            if "exp" in payload and payload["exp"] < time.time():
                return {"valid": False, "error": "Token expired", "payload": payload}

            return {"valid": True, "header": header, "payload": payload}

        except Exception as e:
            return {"valid": False, "error": str(e)}

    def create_id_token(
        self,
        sub: str,
        audience: str,
        nonce: Optional[str] = None,
        name: Optional[str] = None,
        email: Optional[str] = None,
        expires_in: int = 3600,
    ) -> str:
        """
        Create an OIDC ID Token.
        
        Per OpenID Connect Core 1.0 Section 2.
        """
        now = int(time.time())
        payload: dict = {
            "iss": self.issuer,
            "sub": sub,
            "aud": audience,
            "exp": now + expires_in,
            "iat": now,
            "auth_time": now,
            "jti": secrets.token_urlsafe(16),
        }
        if nonce:
            payload["nonce"] = nonce
        if name:
            payload["name"] = name
        if email:
            payload["email"] = email
            payload["email_verified"] = True

        return self._create_jwt(payload)

    def create_access_token(
        self,
        sub: str,
        scope: str,
        audience: str,
        expires_in: int = 3600,
    ) -> str:
        """Create an Access Token as a signed JWT."""
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "sub": sub,
            "aud": audience,
            "exp": now + expires_in,
            "iat": now,
            "scope": scope,
            "jti": secrets.token_urlsafe(16),
            "token_type": "access_token",
        }
        return self._create_jwt(payload)

    def create_refresh_token(
        self,
        sub: str,
        scope: str,
        client_id: str,
        expires_in: int = 86400,
    ) -> str:
        """Create a Refresh Token as a signed JWT."""
        now = int(time.time())
        jti = secrets.token_urlsafe(16)
        payload = {
            "iss": self.issuer,
            "sub": sub,
            "aud": client_id,
            "exp": now + expires_in,
            "iat": now,
            "scope": scope,
            "jti": jti,
            "token_type": "refresh_token",
        }
        token = self._create_jwt(payload)
        self._refresh_tokens[jti] = {
            "sub": sub,
            "scope": scope,
            "client_id": client_id,
            "token": token,
            "issued_at": now,
            "rotated": False,
        }
        return token

    def validate_refresh_token(self, refresh_token: str) -> dict:
        """
        Validate a refresh token and return associated data.
        
        Returns:
            Dict with validation result and token data.
        """
        result = self.verify_jwt(refresh_token)
        if not result["valid"]:
            return result

        payload = result["payload"]
        if payload.get("token_type") != "refresh_token":
            return {"valid": False, "error": "Not a refresh token"}

        jti = payload.get("jti")
        if jti not in self._refresh_tokens:
            return {"valid": False, "error": "Refresh token not found or revoked"}

        stored = self._refresh_tokens[jti]
        if stored.get("rotated"):
            return {"valid": False, "error": "Refresh token already rotated"}

        return {
            "valid": True,
            "sub": payload["sub"],
            "scope": payload["scope"],
            "client_id": payload["aud"],
            "jti": jti,
        }

    def rotate_refresh_token(
        self,
        old_refresh_token: str,
        sub: str,
        scope: str,
        client_id: str,
    ) -> str:
        """
        Rotate a refresh token (invalidate old, issue new).
        
        Returns:
            New refresh token string.
        """
        # Invalidate old token
        old_result = self.verify_jwt(old_refresh_token)
        if old_result.get("valid") and old_result.get("payload"):
            old_jti = old_result["payload"].get("jti")
            if old_jti and old_jti in self._refresh_tokens:
                self._refresh_tokens[old_jti]["rotated"] = True

        return self.create_refresh_token(sub, scope, client_id)

    def issue_token_set(
        self,
        sub: str,
        scope: str,
        client_id: str,
        nonce: Optional[str] = None,
        name: Optional[str] = None,
        email: Optional[str] = None,
    ) -> TokenSet:
        """
        Issue a complete set of OIDC tokens.
        
        Returns:
            TokenSet with id_token, access_token, and refresh_token.
        """
        id_token = self.create_id_token(
            sub=sub,
            audience=client_id,
            nonce=nonce,
            name=name,
            email=email,
        )
        access_token = self.create_access_token(
            sub=sub,
            scope=scope,
            audience=client_id,
        )
        refresh_token = self.create_refresh_token(
            sub=sub,
            scope=scope,
            client_id=client_id,
        )
        return TokenSet(
            id_token=id_token,
            access_token=access_token,
            refresh_token=refresh_token,
            scope=scope,
        )
