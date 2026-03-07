"""
KEMTLS Protocol Engine

Implements a KEMTLS-style handshake protocol using Kyber768 for key encapsulation
and Dilithium3 for server authentication. Derives AES-256-GCM session keys via HKDF.

This is a research prototype implementation of KEMTLS operating above TCP.
The protocol replaces TLS signature-based authentication with KEM-based authentication,
providing post-quantum security for the transport layer.

Handshake Flow:
    1. ClientHello        - Client initiates with supported algorithms
    2. ServerHello        - Server responds with Kyber768 public key
    3. ClientKEMEncap     - Client encapsulates shared secret with server's public key
    4. ServerKEMDecap     - Server decapsulates to derive shared secret
    5. ServerAuth         - Server signs transcript with Dilithium3
    6. ClientVerify       - Client verifies server signature and confirms handshake
"""

import os
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from app.pqcrypto.kem import KyberKEM, KyberKeyPair
from app.pqcrypto.signatures import DilithiumSigner, DilithiumKeyPair


class HandshakeState(str, Enum):
    """States of the KEMTLS handshake."""
    INITIAL = "initial"
    CLIENT_HELLO_SENT = "client_hello_sent"
    SERVER_HELLO_SENT = "server_hello_sent"
    CLIENT_KEM_ENCAP = "client_kem_encap"
    SERVER_KEM_DECAP = "server_kem_decap"
    SERVER_AUTH = "server_auth"
    CLIENT_VERIFY = "client_verify"
    ESTABLISHED = "established"
    FAILED = "failed"


@dataclass
class HandshakeMessage:
    """Represents a single KEMTLS handshake message."""
    msg_type: str
    payload: dict
    timestamp: float = field(default_factory=time.time)
    size_bytes: int = 0


@dataclass
class HandshakeLog:
    """Complete log of a KEMTLS handshake."""
    messages: list = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    state: HandshakeState = HandshakeState.INITIAL
    shared_secret_derived: bool = False
    session_key_derived: bool = False

    @property
    def total_latency_ms(self) -> float:
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0

    @property
    def total_bytes_exchanged(self) -> int:
        return sum(m.size_bytes for m in self.messages)


@dataclass
class KEMTLSSession:
    """Represents an established KEMTLS session."""
    session_id: str
    session_key: bytes
    handshake_log: HandshakeLog
    kem_algorithm: str = "Kyber768"
    sig_algorithm: str = "Dilithium3"
    cipher_suite: str = "AES-256-GCM"

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "kem_algorithm": self.kem_algorithm,
            "sig_algorithm": self.sig_algorithm,
            "cipher_suite": self.cipher_suite,
            "handshake_latency_ms": self.handshake_log.total_latency_ms,
            "bytes_exchanged": self.handshake_log.total_bytes_exchanged,
            "state": self.handshake_log.state.value,
            "messages": [
                {
                    "type": m.msg_type,
                    "size_bytes": m.size_bytes,
                    "timestamp": m.timestamp,
                }
                for m in self.handshake_log.messages
            ],
        }


class KEMTLSServer:
    """
    KEMTLS Server-side protocol implementation.
    
    The server generates a Kyber768 keypair for key exchange and a Dilithium3
    keypair for authentication. During the handshake, it decapsulates the
    client's KEM ciphertext and signs the handshake transcript.
    """

    def __init__(self) -> None:
        self.kem = KyberKEM()
        self.signer = DilithiumSigner()
        self.kem_keypair: Optional[KyberKeyPair] = None
        self.sig_keypair: Optional[DilithiumKeyPair] = None
        self.shared_secret: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.handshake_log = HandshakeLog()
        self._transcript = b""

    def initialize(self) -> None:
        """Generate server key pairs for KEM and signatures."""
        self.kem_keypair = self.kem.generate_keypair()
        self.sig_keypair = self.signer.generate_keypair()

    def process_client_hello(self, client_hello: dict) -> dict:
        """
        Process ClientHello and generate ServerHello.
        
        Args:
            client_hello: Client's hello message with supported algorithms.
            
        Returns:
            ServerHello message with server's KEM public key.
        """
        self.handshake_log.start_time = time.perf_counter()
        self.handshake_log.state = HandshakeState.CLIENT_HELLO_SENT

        # Log ClientHello
        client_hello_bytes = str(client_hello).encode()
        self._transcript += client_hello_bytes
        self.handshake_log.messages.append(HandshakeMessage(
            msg_type="ClientHello",
            payload=client_hello,
            size_bytes=len(client_hello_bytes),
        ))

        if self.kem_keypair is None:
            self.initialize()

        assert self.kem_keypair is not None
        assert self.sig_keypair is not None

        # Build ServerHello
        server_hello = {
            "kem_algorithm": "Kyber768",
            "sig_algorithm": "Dilithium3",
            "kem_public_key": self.kem_keypair.public_key.hex(),
            "sig_public_key": self.sig_keypair.public_key.hex(),
            "server_random": os.urandom(32).hex(),
        }

        server_hello_bytes = str(server_hello).encode()
        self._transcript += server_hello_bytes
        self.handshake_log.messages.append(HandshakeMessage(
            msg_type="ServerHello",
            payload={
                "kem_algorithm": "Kyber768",
                "sig_algorithm": "Dilithium3",
                "kem_public_key_size": len(self.kem_keypair.public_key),
                "sig_public_key_size": len(self.sig_keypair.public_key),
            },
            size_bytes=len(self.kem_keypair.public_key) + len(self.sig_keypair.public_key) + 32,
        ))
        self.handshake_log.state = HandshakeState.SERVER_HELLO_SENT

        return server_hello

    def process_client_kem_encap(self, ciphertext_hex: str) -> dict:
        """
        Process client's KEM encapsulation (ServerKEMDecap step).
        
        Args:
            ciphertext_hex: Hex-encoded KEM ciphertext from client.
            
        Returns:
            ServerAuth message with signed transcript.
        """
        assert self.kem_keypair is not None
        assert self.sig_keypair is not None

        ciphertext = bytes.fromhex(ciphertext_hex)

        # Log ClientKEMEncap
        self._transcript += ciphertext
        self.handshake_log.messages.append(HandshakeMessage(
            msg_type="ClientKEMEncap",
            payload={"ciphertext_size": len(ciphertext)},
            size_bytes=len(ciphertext),
        ))
        self.handshake_log.state = HandshakeState.CLIENT_KEM_ENCAP

        # ServerKEMDecap - decapsulate shared secret
        self.shared_secret = self.kem.decapsulate(ciphertext, self.kem_keypair.secret_key)
        self.handshake_log.messages.append(HandshakeMessage(
            msg_type="ServerKEMDecap",
            payload={"shared_secret_derived": True, "shared_secret_size": len(self.shared_secret)},
            size_bytes=0,  # Internal operation, no bytes on wire
        ))
        self.handshake_log.state = HandshakeState.SERVER_KEM_DECAP
        self.handshake_log.shared_secret_derived = True

        # Derive session key using HKDF
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"kemtls-session-key",
        ).derive(self.shared_secret)
        self.handshake_log.session_key_derived = True

        # ServerAuth - sign the transcript
        transcript_hash = hashlib.sha256(self._transcript).digest()
        signature = self.signer.sign(transcript_hash, self.sig_keypair.secret_key)

        server_auth = {
            "transcript_hash": transcript_hash.hex(),
            "signature": signature.hex(),
            "sig_algorithm": "Dilithium3",
        }

        server_auth_bytes = str(server_auth).encode()
        self._transcript += server_auth_bytes
        self.handshake_log.messages.append(HandshakeMessage(
            msg_type="ServerAuth",
            payload={"signature_size": len(signature), "sig_algorithm": "Dilithium3"},
            size_bytes=len(signature),
        ))
        self.handshake_log.state = HandshakeState.SERVER_AUTH

        return server_auth

    def finalize(self) -> KEMTLSSession:
        """
        Finalize the handshake after client verification.
        
        Returns:
            Established KEMTLSSession.
        """
        assert self.session_key is not None

        self.handshake_log.messages.append(HandshakeMessage(
            msg_type="ClientVerify",
            payload={"verified": True},
            size_bytes=1,
        ))
        self.handshake_log.state = HandshakeState.ESTABLISHED
        self.handshake_log.end_time = time.perf_counter()

        session_id = os.urandom(16).hex()
        return KEMTLSSession(
            session_id=session_id,
            session_key=self.session_key,
            handshake_log=self.handshake_log,
        )


class KEMTLSClient:
    """
    KEMTLS Client-side protocol implementation.
    
    The client initiates the handshake, encapsulates a shared secret using
    the server's Kyber768 public key, and verifies the server's Dilithium3
    signature on the handshake transcript.
    """

    def __init__(self) -> None:
        self.kem = KyberKEM()
        self.signer = DilithiumSigner()
        self.shared_secret: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.handshake_log = HandshakeLog()
        self._transcript = b""
        self._server_sig_public_key: Optional[bytes] = None

    def create_client_hello(self) -> dict:
        """
        Create a ClientHello message.
        
        Returns:
            ClientHello message with supported algorithms.
        """
        self.handshake_log.start_time = time.perf_counter()

        client_hello = {
            "supported_kems": ["Kyber768"],
            "supported_sigs": ["Dilithium3"],
            "client_random": os.urandom(32).hex(),
        }

        client_hello_bytes = str(client_hello).encode()
        self._transcript += client_hello_bytes
        self.handshake_log.messages.append(HandshakeMessage(
            msg_type="ClientHello",
            payload=client_hello,
            size_bytes=len(client_hello_bytes),
        ))
        self.handshake_log.state = HandshakeState.CLIENT_HELLO_SENT

        return client_hello

    def process_server_hello(self, server_hello: dict) -> str:
        """
        Process ServerHello and perform KEM encapsulation.
        
        Args:
            server_hello: Server's hello message with KEM public key.
            
        Returns:
            Hex-encoded ciphertext for the server.
        """
        server_hello_bytes = str(server_hello).encode()
        self._transcript += server_hello_bytes
        self.handshake_log.messages.append(HandshakeMessage(
            msg_type="ServerHello",
            payload={
                "kem_algorithm": server_hello["kem_algorithm"],
                "sig_algorithm": server_hello["sig_algorithm"],
            },
            size_bytes=len(server_hello_bytes),
        ))
        self.handshake_log.state = HandshakeState.SERVER_HELLO_SENT

        # Store server's signature public key for verification
        self._server_sig_public_key = bytes.fromhex(server_hello["sig_public_key"])

        # ClientKEMEncap - encapsulate shared secret
        server_kem_pk = bytes.fromhex(server_hello["kem_public_key"])
        result = self.kem.encapsulate(server_kem_pk)

        self.shared_secret = result.shared_secret
        self.handshake_log.shared_secret_derived = True

        self._transcript += result.ciphertext
        self.handshake_log.messages.append(HandshakeMessage(
            msg_type="ClientKEMEncap",
            payload={"ciphertext_size": len(result.ciphertext)},
            size_bytes=len(result.ciphertext),
        ))
        self.handshake_log.state = HandshakeState.CLIENT_KEM_ENCAP

        # Derive session key
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"kemtls-session-key",
        ).derive(self.shared_secret)
        self.handshake_log.session_key_derived = True

        return result.ciphertext.hex()

    def verify_server_auth(self, server_auth: dict) -> bool:
        """
        Verify the server's authentication signature (ClientVerify step).
        
        Args:
            server_auth: Server's auth message with signed transcript.
            
        Returns:
            True if server authentication is valid.
        """
        assert self._server_sig_public_key is not None

        transcript_hash = hashlib.sha256(self._transcript).digest()
        expected_hash = bytes.fromhex(server_auth["transcript_hash"])

        # Verify transcript hashes match
        if transcript_hash != expected_hash:
            self.handshake_log.state = HandshakeState.FAILED
            return False

        # Verify Dilithium3 signature
        signature = bytes.fromhex(server_auth["signature"])
        is_valid = self.signer.verify(transcript_hash, signature, self._server_sig_public_key)

        if is_valid:
            server_auth_bytes = str(server_auth).encode()
            self._transcript += server_auth_bytes
            self.handshake_log.messages.append(HandshakeMessage(
                msg_type="ServerAuth",
                payload={"verified": True},
                size_bytes=len(signature),
            ))
            self.handshake_log.state = HandshakeState.SERVER_AUTH

            self.handshake_log.messages.append(HandshakeMessage(
                msg_type="ClientVerify",
                payload={"verified": True},
                size_bytes=1,
            ))
            self.handshake_log.state = HandshakeState.ESTABLISHED
            self.handshake_log.end_time = time.perf_counter()
        else:
            self.handshake_log.state = HandshakeState.FAILED

        return is_valid

    def get_session(self) -> Optional[KEMTLSSession]:
        """
        Get the established session after successful handshake.
        
        Returns:
            KEMTLSSession if handshake was successful, None otherwise.
        """
        if self.handshake_log.state != HandshakeState.ESTABLISHED or self.session_key is None:
            return None

        session_id = os.urandom(16).hex()
        return KEMTLSSession(
            session_id=session_id,
            session_key=self.session_key,
            handshake_log=self.handshake_log,
        )


def perform_kemtls_handshake() -> tuple[KEMTLSSession, KEMTLSSession]:
    """
    Perform a complete KEMTLS handshake between client and server.
    
    Returns:
        Tuple of (server_session, client_session).
        
    Raises:
        RuntimeError: If handshake fails.
    """
    server = KEMTLSServer()
    client = KEMTLSClient()

    # Step 1: ClientHello
    client_hello = client.create_client_hello()

    # Step 2: ServerHello
    server_hello = server.process_client_hello(client_hello)

    # Step 3: ClientKEMEncap
    ciphertext_hex = client.process_server_hello(server_hello)

    # Step 4-5: ServerKEMDecap + ServerAuth
    server_auth = server.process_client_kem_encap(ciphertext_hex)

    # Step 6: ClientVerify
    verified = client.verify_server_auth(server_auth)
    if not verified:
        raise RuntimeError("KEMTLS handshake failed: server authentication invalid")

    server_session = server.finalize()
    client_session = client.get_session()
    if client_session is None:
        raise RuntimeError("KEMTLS handshake failed: client session not established")

    return server_session, client_session
