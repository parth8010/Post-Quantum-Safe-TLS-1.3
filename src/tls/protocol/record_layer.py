
import logging
import struct
from enum import Enum
from typing import Optional, Tuple

from ..crypto.cipher_suites import CipherSuiteFactory

logger = logging.getLogger("TLSRecord")

class ContentType(Enum):
    """RFC 8446 5.1 - TLS Record Content Type"""
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

class TLSRecordLayer:
    """RFC 8446 5 - TLS Record Layer
    
    Handles record framing, encryption/decryption, and per-record nonce construction.
    """
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.sequence_number = 0
        self.write_key = None
        self.write_iv = None
        self.cipher_suite = None
        self.encryption_enabled = False
        
    def enable_encryption(self, cipher_suite_name: str, keys: dict):
        """Enable AEAD encryption on record layer
        
        Args:
            cipher_suite_name: Name of cipher suite (e.g., "TLS_AES_256_GCM_SHA384")
            keys: Dict with 'key' and 'iv' for write direction
        """
        self.write_key = keys['key']
        self.write_iv = keys['iv']
        self.cipher_suite = CipherSuiteFactory.create_cipher_suite(
            cipher_suite_name,
            self.write_key,
            self.write_iv
        )
        self.encryption_enabled = True
        self.sequence_number = 0  # Reset sequence number when enabling encryption
        logger.info(f"Encryption enabled: {cipher_suite_name}, key={len(self.write_key)} bytes, iv={len(self.write_iv)} bytes")
    
    def _construct_nonce(self) -> bytes:
        """RFC 8446 5.3 - Per-Record Nonce Construction
        
        1. Encode 64-bit sequence number in network byte order
        2. Pad left with zeros to iv_length
        3. XOR with static write_iv
        """
        if self.write_iv is None:
            raise ValueError("Write IV not initialized")
        
        iv_length = len(self.write_iv)
        
        # Step 1: Encode sequence number (8 bytes)
        seq_bytes = self.sequence_number.to_bytes(8, byteorder='big')
        
        # Step 2: Pad left to iv_length
        seq_padded = (b'\x00' * (iv_length - 8)) + seq_bytes
        
        # Step 3: XOR with IV
        nonce = bytes(a ^ b for a, b in zip(self.write_iv, seq_padded))
        
        logger.debug(f"Nonce constructed: seq={self.sequence_number}, nonce={nonce.hex()[:16]}...")
        return nonce
    
    def _increment_sequence_number(self):
        """Increment sequence number after each record (RFC 8446 5.3)"""
        self.sequence_number += 1
        if self.sequence_number >= (1 << 64):
            # Sequence number overflow - MUST rekey or terminate connection
            logger.error("Sequence number overflow - must trigger key update or close connection")
            self.sequence_number = 0  # For now, reset (not spec-compliant)
    
    def protect_record(self, plaintext: bytes, content_type: ContentType) -> bytes:
        """RFC 8446 5.2 - Record Payload Protection
        
        Encrypts plaintext with AEAD and returns TLSCiphertext structure.
        
        Args:
            plaintext: Data to encrypt
            content_type: Original content type (will be hidden in encrypted record)
        
        Returns:
            TLSCiphertext bytes: [opaque_type(1) | legacy_version(2) | length(2) | encrypted(n)]
        """
        if not self.encryption_enabled:
            # Return unencrypted record for plaintext data (before handshake)
            return self._create_plaintext_record(plaintext, content_type)
        
        # Build TLSInnerPlaintext (RFC 8446 5.2)
        # struct {
        #     opaque content[TLSPlaintext.length];
        #     ContentType type;
        #     uint8 zeros[length_of_padding];
        # } TLSInnerPlaintext;
        
        inner_plaintext = plaintext + struct.pack('>B', content_type.value)
        
        # No padding for now (add padding option later if needed)
        # Optional: add zero-valued bytes for padding
        
        # Construct nonce (RFC 8446 5.3)
        nonce = self._construct_nonce()
        
        # Compute encrypted record length for AAD
        # encrypted_record = ciphertext || auth_tag
        # For AES-256-GCM: auth_tag is 16 bytes
        # encrypted_length = len(inner_plaintext) + 16 (auth tag)
        encrypted_length = len(inner_plaintext) + 16
        
        # Additional Authenticated Data (RFC 8446 5.2)
        # additional_data = TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
        aad = (
            struct.pack('>B', 23) +  # opaque_type = application_data
            struct.pack('>H', 0x0303) +  # legacy_record_version = TLS 1.2
            struct.pack('>H', encrypted_length)  # length of encrypted_record
        )
        
        # Encrypt using AEAD with AAD
        try:
            ciphertext, auth_tag = self.cipher_suite.encrypt(inner_plaintext, aad)
            
            self._increment_sequence_number()
            
            # Build TLSCiphertext
            # struct {
            #     ContentType opaque_type = application_data; /* 23 */
            #     ProtocolVersion legacy_record_version = 0x0303;
            #     uint16 length;
            #     opaque encrypted_record[TLSCiphertext.length];
            # } TLSCiphertext;
            
            encrypted_record = ciphertext + auth_tag
            tlsciphertext = (
                struct.pack('>B', 23) +  # opaque_type = application_data
                struct.pack('>H', 0x0303) +  # legacy_record_version
                struct.pack('>H', len(encrypted_record)) +  # length
                encrypted_record  # encrypted_record
            )
            
            logger.debug(f"Record protected: plaintext={len(plaintext)}, encrypted={len(encrypted_record)}, total={len(tlsciphertext)}")
            return tlsciphertext
            
        except Exception as e:
            logger.error(f"Failed to encrypt record: {e}")
            raise
    
    def unprotect_record(self, ciphertext_record: bytes) -> Tuple[bytes, ContentType]:
        """RFC 8446 5.2 - Record Payload Unprotection
        
        Decrypts and verifies TLSCiphertext, returns plaintext and original content type.
        
        Args:
            ciphertext_record: Encrypted TLS record bytes
        
        Returns:
            Tuple[plaintext, content_type]
        """
        if not self.encryption_enabled:
            # Parse unencrypted record
            return self._parse_plaintext_record(ciphertext_record)
        
        # Parse TLSCiphertext header (5 bytes)
        if len(ciphertext_record) < 5:
            raise ValueError(f"Record too short: {len(ciphertext_record)} bytes")
        
        opaque_type = ciphertext_record[0]
        legacy_version = struct.unpack('>H', ciphertext_record[1:3])[0]
        encrypted_length = struct.unpack('>H', ciphertext_record[3:5])[0]
        
        # Validate record format
        if opaque_type != 23:  # Must be application_data (23)
            raise ValueError(f"Invalid opaque_type: {opaque_type}, expected 23")
        if legacy_version != 0x0303:  # Must be TLS 1.2 legacy version
            logger.warning(f"Unexpected legacy_version: 0x{legacy_version:04x}")
        
        # Extract encrypted data
        if len(ciphertext_record) < 5 + encrypted_length:
            raise ValueError(f"Record incomplete: expected {encrypted_length}, got {len(ciphertext_record) - 5}")
        
        encrypted_record = ciphertext_record[5:5 + encrypted_length]
        
        # Split ciphertext and auth tag
        # Auth tag is last 16 bytes for GCM
        auth_tag_length = 16
        if len(encrypted_record) < auth_tag_length:
            raise ValueError(f"Encrypted record too short for auth tag")
        
        ciphertext = encrypted_record[:-auth_tag_length]
        auth_tag = encrypted_record[-auth_tag_length:]
        
        # Construct nonce (RFC 8446 5.3)
        nonce = self._construct_nonce()
        
        # Reconstruct AAD
        aad = (
            struct.pack('>B', 23) +  # opaque_type
            struct.pack('>H', 0x0303) +  # legacy_record_version
            struct.pack('>H', len(encrypted_record))  # length
        )
        
        # Decrypt using AEAD
        try:
            inner_plaintext = self.cipher_suite.decrypt(ciphertext, auth_tag, aad)
            
            self._increment_sequence_number()
            
            # Parse TLSInnerPlaintext
            # Last byte is ContentType, rest is content
            if len(inner_plaintext) < 1:
                raise ValueError("Inner plaintext too short")
            
            content_type_value = inner_plaintext[-1]
            plaintext = inner_plaintext[:-1]
            
            # Remove trailing zeros (padding)
            while len(plaintext) > 0 and plaintext[-1] == 0:
                plaintext = plaintext[:-1]
            
            # Validate content type
            try:
                content_type = ContentType(content_type_value)
            except ValueError:
                raise ValueError(f"Invalid content type in encrypted record: {content_type_value}")
            
            logger.debug(f"Record unprotected: encrypted={len(encrypted_record)}, plaintext={len(plaintext)}, type={content_type.name}")
            return plaintext, content_type
            
        except Exception as e:
            logger.error(f"Failed to decrypt record: {e}")
            raise
    
    def _create_plaintext_record(self, data: bytes, content_type: ContentType) -> bytes:
        """Create unencrypted TLSPlaintext record"""
        return (
            struct.pack('>B', content_type.value) +  # type
            struct.pack('>H', 0x0303) +  # legacy_record_version (TLS 1.2)
            struct.pack('>H', len(data)) +  # length
            data  # fragment
        )
    
    def _parse_plaintext_record(self, record_data: bytes) -> Tuple[bytes, ContentType]:
        """Parse unencrypted TLSPlaintext record"""
        if len(record_data) < 5:
            raise ValueError(f"Record too short: {len(record_data)}")
        
        content_type_value = record_data[0]
        legacy_version = struct.unpack('>H', record_data[1:3])[0]
        length = struct.unpack('>H', record_data[3:5])[0]
        
        if len(record_data) < 5 + length:
            raise ValueError(f"Record incomplete: expected {length}, got {len(record_data) - 5}")
        
        data = record_data[5:5 + length]
        
        try:
            content_type = ContentType(content_type_value)
        except ValueError:
            content_type = ContentType.APPLICATION_DATA  # Default to app data
        
        return data, content_type


class TLSRecordManager:
    """Manages TLS record layer for client/server connection"""
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.record_layer = TLSRecordLayer(is_server)
        self.handshake_buffer = b""
        
    def send_record(self, data: bytes, content_type: ContentType) -> bytes:
        """Send a record with optional encryption"""
        return self.record_layer.protect_record(data, content_type)
    
    def receive_records(self, data: bytes) -> list:
        """Parse incoming data into records and messages
        
        Returns list of tuples: (message_type, message_data)
        """
        messages = []
        remaining_data = data
        
        while len(remaining_data) >= 5:  # Minimum record header
            try:
                # Parse record header
                record_type = remaining_data[0]
                record_length = struct.unpack('>H', remaining_data[3:5])[0]
                total_length = 5 + record_length
                
                if len(remaining_data) < total_length:
                    break  # Incomplete record
                
                record_data = remaining_data[:total_length]
                
                # Unprotect record (decrypt if needed)
                plaintext, content_type = self.record_layer.unprotect_record(record_data)
                
                # Process by content type
                if content_type == ContentType.HANDSHAKE:
                    self.handshake_buffer += plaintext
                    messages.extend(self._extract_handshake_messages())
                elif content_type == ContentType.APPLICATION_DATA:
                    messages.append(('application_data', plaintext))
                elif content_type == ContentType.ALERT:
                    messages.append(('alert', plaintext))
                elif content_type == ContentType.CHANGE_CIPHER_SPEC:
                    messages.append(('change_cipher_spec', plaintext))
                
                remaining_data = remaining_data[total_length:]
                
            except Exception as e:
                logger.error(f"Error processing record: {e}")
                break
        
        return messages
    
    def _extract_handshake_messages(self) -> list:
        """Extract individual handshake messages from buffer"""
        messages = []
        
        while len(self.handshake_buffer) >= 4:
            try:
                # Parse handshake message header
                # Handshake: type (1) + length (3)
                msg_type = self.handshake_buffer[0]
                msg_length = struct.unpack('>I', b'\x00' + self.handshake_buffer[1:4])[0]
                total_length = 4 + msg_length
                
                if len(self.handshake_buffer) < total_length:
                    break  # Incomplete message
                
                message_data = self.handshake_buffer[:total_length]
                messages.append(('handshake', message_data))
                
                self.handshake_buffer = self.handshake_buffer[total_length:]
                
            except struct.error:
                break
        
        return messages
    
    def enable_encryption(self, cipher_suite_name: str, keys: dict):
        """Enable encryption on the record layer"""
        self.record_layer.enable_encryption(cipher_suite_name, keys)
    
    def receive_data(self, data: bytes) -> Tuple[list, bytes]:
        """Receive and process data from socket
        
        Returns:
            Tuple of (messages, remaining_buffer)
            where messages is a list of (msg_type, msg_data) tuples
        """
        messages = []
        remaining_data = data
        
        while len(remaining_data) >= 5:  # Minimum record header
            try:
                # Parse record header to get full record
                record_length = struct.unpack('>H', remaining_data[3:5])[0]
                total_length = 5 + record_length
                
                if len(remaining_data) < total_length:
                    break  # Incomplete record, keep in buffer
                
                record_data = remaining_data[:total_length]
                
                # Unprotect record (decrypt if needed)
                try:
                    plaintext, content_type = self.record_layer.unprotect_record(record_data)
                    
                    # Process by content type
                    if content_type == ContentType.HANDSHAKE:
                        self.handshake_buffer += plaintext
                        messages.extend(self._extract_handshake_messages())
                    elif content_type == ContentType.APPLICATION_DATA:
                        messages.append(('application_data', plaintext))
                    elif content_type == ContentType.ALERT:
                        messages.append(('alert', plaintext))
                    elif content_type == ContentType.CHANGE_CIPHER_SPEC:
                        messages.append(('change_cipher_spec', plaintext))
                        
                except Exception as e:
                    logger.error(f"Error decrypting record: {e}")
                    # Skip this record and continue
                
                remaining_data = remaining_data[total_length:]
                
            except Exception as e:
                logger.error(f"Error processing record: {e}")
                break
        
        return messages, remaining_data
    
    def send_application_data(self, data: bytes) -> bytes:
        """Encrypt and send application data
        
        Args:
            data: Application data bytes to send
            
        Returns:
            Encrypted record bytes ready to send over socket
        """
        return self.record_layer.protect_record(data, ContentType.APPLICATION_DATA)