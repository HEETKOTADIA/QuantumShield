"""
KEMTLS Secure Channel

Implements AES-256-GCM encrypted communication channel using the session key
derived from the KEMTLS handshake.
"""

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class EncryptedMessage:
    """An encrypted message with nonce and associated data."""
    nonce: bytes
    ciphertext: bytes
    aad: bytes  # Additional Authenticated Data

    def to_bytes(self) -> bytes:
        """Serialize to bytes for transmission."""
        nonce_len = struct.pack(">H", len(self.nonce))
        aad_len = struct.pack(">H", len(self.aad))
        ct_len = struct.pack(">I", len(self.ciphertext))
        return nonce_len + self.nonce + aad_len + self.aad + ct_len + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedMessage":
        """Deserialize from bytes."""
        offset = 0
        nonce_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        nonce = data[offset:offset + nonce_len]
        offset += nonce_len
        aad_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        aad = data[offset:offset + aad_len]
        offset += aad_len
        ct_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        ciphertext = data[offset:offset + ct_len]
        return cls(nonce=nonce, ciphertext=ciphertext, aad=aad)

    def total_size(self) -> int:
        return len(self.nonce) + len(self.ciphertext) + len(self.aad)


class SecureChannel:
    """
    AES-256-GCM Secure Channel.
    
    Uses the 256-bit session key derived from the KEMTLS handshake
    to encrypt and authenticate all communication.
    """

    def __init__(self, session_key: bytes) -> None:
        """
        Initialize the secure channel.
        
        Args:
            session_key: 32-byte AES-256 key from KEMTLS handshake.
        """
        if len(session_key) != 32:
            raise ValueError("Session key must be 32 bytes for AES-256-GCM")
        self._aesgcm = AESGCM(session_key)
        self._message_counter = 0

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"kemtls") -> EncryptedMessage:
        """
        Encrypt a message using AES-256-GCM.
        
        Args:
            plaintext: The data to encrypt.
            associated_data: Additional authenticated data (not encrypted but authenticated).
            
        Returns:
            EncryptedMessage containing nonce and ciphertext.
        """
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        self._message_counter += 1
        return EncryptedMessage(nonce=nonce, ciphertext=ciphertext, aad=associated_data)

    def decrypt(self, message: EncryptedMessage) -> bytes:
        """
        Decrypt a message using AES-256-GCM.
        
        Args:
            message: The EncryptedMessage to decrypt.
            
        Returns:
            Decrypted plaintext bytes.
            
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails.
        """
        plaintext = self._aesgcm.decrypt(message.nonce, message.ciphertext, message.aad)
        return plaintext

    @property
    def messages_processed(self) -> int:
        return self._message_counter
