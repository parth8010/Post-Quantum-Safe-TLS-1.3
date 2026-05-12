# TLS 1.3 Cipher Suites Implementation (RFC 8446)
# AES-GCM and ChaCha20-Poly1305 encryption/decryption

import os
import logging
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("TLSCipher")

class CipherSuite:
    """Base class for AEAD cipher suites"""
    
    def __init__(self, key: bytes, iv: bytes):
        self.key = key
        self.iv = iv
        self.sequence_number = 0
        
    def encrypt(self, plaintext: bytes, additional_data: bytes = b"") -> tuple:
        """Encrypt plaintext with associated data
        
        Returns: (ciphertext, auth_tag)
        """
        raise NotImplementedError
        
    def decrypt(self, ciphertext: bytes, auth_tag: bytes, additional_data: bytes = b"") -> bytes:
        """Decrypt ciphertext with associated data verification"""
        raise NotImplementedError
        
    def update_sequence_number(self):
        """Update sequence number for next record"""
        self.sequence_number += 1
        if self.sequence_number >= (1 << 64):
            # Sequence number overflow
            logger.warning("Sequence number overflow - must trigger key update")
            self.sequence_number = 0


class AESGCM(CipherSuite):
    """RFC 8446 - AES-256-GCM cipher suite"""
    
    def __init__(self, key: bytes, iv: bytes):
        super().__init__(key, iv)
        self.nonce_length = len(iv)  # Should be 12 bytes for standard AEAD
        if self.nonce_length != 12:
            logger.warning(f"AES-GCM IV length: {self.nonce_length}, expected 12")
        
    def encrypt(self, plaintext: bytes, additional_data: bytes = b"") -> tuple:
        """RFC 8446 5.2 - AES-256-GCM encryption with AEAD
        
        Args:
            plaintext: Data to encrypt (includes content type and padding)
            additional_data: TLSCiphertext header (5 bytes: type + version + length)
        
        Returns:
            (ciphertext, auth_tag) - ciphertext + auth_tag = encrypted_record
        """
        try:
            # Construct nonce - should be constructed by record layer
            # For now, use sequence number-based nonce
            nonce = self._construct_nonce()
            
            # Create AES-GCM cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            
            # Encrypt with additional data
            encryptor = cipher.encryptor()
            
            # Add authenticated data (not encrypted, but authenticated)
            if additional_data:
                encryptor.authenticate_additional_data(additional_data)
            
            # Encrypt plaintext
            ciphertext = encryptor.update(plaintext)
            ciphertext += encryptor.finalize()
            
            # Get authentication tag (16 bytes for GCM)
            auth_tag = encryptor.tag
            
            self.update_sequence_number()
            
            logger.debug(f"AES-256-GCM encrypted: plaintext={len(plaintext)} bytes, "
                        f"aad={len(additional_data)} bytes, tag_length={len(auth_tag)} bytes")
            
            return ciphertext, auth_tag
            
        except Exception as e:
            logger.error(f"AES-GCM encryption failed: {e}")
            raise
    
    def decrypt(self, ciphertext: bytes, auth_tag: bytes, additional_data: bytes = b"") -> bytes:
        """RFC 8446 5.2 - AES-256-GCM decryption with AEAD authentication
        
        Args:
            ciphertext: Encrypted data
            auth_tag: Authentication tag (16 bytes)
            additional_data: TLSCiphertext header for authentication
        
        Returns:
            plaintext if authentication succeeds
        
        Raises:
            Exception if authentication fails
        """
        try:
            # Construct nonce
            nonce = self._construct_nonce()
            
            # Create AES-GCM cipher with tag
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce, auth_tag),
                backend=default_backend()
            )
            
            # Decrypt with authentication
            decryptor = cipher.decryptor()
            
            # Add authenticated data
            if additional_data:
                decryptor.authenticate_additional_data(additional_data)
            
            # Decrypt and verify
            plaintext = decryptor.update(ciphertext)
            plaintext += decryptor.finalize()  # Raises if authentication fails
            
            self.update_sequence_number()
            
            logger.debug(f"AES-256-GCM decrypted: ciphertext={len(ciphertext)} bytes, "
                        f"aad={len(additional_data)} bytes, plaintext={len(plaintext)} bytes")
            
            return plaintext
            
        except Exception as e:
            logger.error(f"AES-GCM decryption/authentication failed: {e}")
            raise
    
    def _construct_nonce(self) -> bytes:
        """Construct nonce from IV and sequence number
        
        Should be overridden by record layer implementation.
        This is a simple version for testing.
        """
        # Pad sequence number to 8 bytes
        seq_bytes = self.sequence_number.to_bytes(8, byteorder='big')
        # Pad to nonce length
        seq_padded = b'\x00' * (self.nonce_length - 8) + seq_bytes
        # XOR with IV
        nonce = bytes(a ^ b for a, b in zip(self.iv, seq_padded))
        return nonce


class ChaCha20Poly1305(CipherSuite):
    """RFC 8446 - ChaCha20-Poly1305 cipher suite"""
    
    def __init__(self, key: bytes, iv: bytes):
        super().__init__(key, iv)
        self.nonce_length = 12  # ChaCha20 uses 12-byte nonce
        
    def encrypt(self, plaintext: bytes, additional_data: bytes = b"") -> tuple:
        """ChaCha20-Poly1305 encryption"""
        try:
            nonce = self._construct_nonce()
            
            # Create ChaCha20Poly1305 cipher
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            cipher = ChaCha20Poly1305(self.key)
            
            # Encrypt with AAD
            ciphertext = cipher.encrypt(nonce, plaintext, additional_data)
            
            # ChaCha20Poly1305 returns ciphertext + tag together
            # Split to match interface
            auth_tag = ciphertext[-16:]
            ciphertext = ciphertext[:-16]
            
            self.update_sequence_number()
            
            logger.debug(f"ChaCha20-Poly1305 encrypted: {len(plaintext)} bytes")
            return ciphertext, auth_tag
            
        except Exception as e:
            logger.error(f"ChaCha20-Poly1305 encryption failed: {e}")
            raise
    
    def decrypt(self, ciphertext: bytes, auth_tag: bytes, additional_data: bytes = b"") -> bytes:
        """ChaCha20-Poly1305 decryption"""
        try:
            nonce = self._construct_nonce()
            
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            cipher = ChaCha20Poly1305(self.key)
            
            # Combine ciphertext and tag for decryption
            ciphertext_with_tag = ciphertext + auth_tag
            
            # Decrypt and verify
            plaintext = cipher.decrypt(nonce, ciphertext_with_tag, additional_data)
            
            self.update_sequence_number()
            
            logger.debug(f"ChaCha20-Poly1305 decrypted: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            logger.error(f"ChaCha20-Poly1305 decryption failed: {e}")
            raise
    
    def _construct_nonce(self) -> bytes:
        """Construct ChaCha20 nonce from IV and sequence number"""
        seq_bytes = self.sequence_number.to_bytes(8, byteorder='big')
        seq_padded = b'\x00' * 4 + seq_bytes
        nonce = bytes(a ^ b for a, b in zip(self.iv, seq_padded))
        return nonce


class CipherSuiteFactory:
    """Factory for creating cipher suite instances"""
    
    @staticmethod
    def create_cipher_suite(suite_name: str, key: bytes, iv: bytes) -> CipherSuite:
        """Create a cipher suite instance
        
        Args:
            suite_name: Cipher suite name
            key: Symmetric key bytes
            iv: Initialization vector/nonce bytes
        
        Returns:
            CipherSuite instance
        """
        if suite_name == "TLS_AES_256_GCM_SHA384":
            return AESGCM(key, iv)
        elif suite_name == "TLS_AES_128_GCM_SHA256":
            return AESGCM(key, iv)
        elif suite_name == "TLS_CHACHA20_POLY1305_SHA256":
            return ChaCha20Poly1305(key, iv)
        else:
            raise ValueError(f"Unsupported cipher suite: {suite_name}")
    
    @staticmethod
    def get_key_iv_lengths(suite_name: str) -> tuple:
        """Get required key and IV lengths for cipher suite
        
        Returns:
            (key_length, iv_length) in bytes
        """
        if suite_name == "TLS_AES_256_GCM_SHA384":
            return 32, 12  # AES-256 key, 12-byte IV
        elif suite_name == "TLS_AES_128_GCM_SHA256":
            return 16, 12  # AES-128 key, 12-byte IV
        elif suite_name == "TLS_CHACHA20_POLY1305_SHA256":
            return 32, 12  # ChaCha20 key, 12-byte nonce
        else:
            raise ValueError(f"Unsupported cipher suite: {suite_name}")