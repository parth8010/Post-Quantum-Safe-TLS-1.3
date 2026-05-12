
# Handles key derivation according to TLS 1.3 (RFC 8446 Section 7.1)

import logging
import struct
from .foundation import hkdf_extract, hkdf_expand_label

logger = logging.getLogger("TLSKeySchedule")

class TLSKeySchedule:
    """RFC 8446 Section 7.1 - TLS 1.3 Key Schedule
    
    Uses HKDF-Extract and HKDF-Expand-Label for key derivation.
    Supports TLS_AES_256_GCM_SHA384 cipher suite.
    """
    
    # Cipher suite parameters
    HASH_LENGTH = 48  # SHA384 output length in bytes
    KEY_LENGTH = 32   # AES-256 key length
    IV_LENGTH = 12    # AEAD IV/nonce length
    
    def __init__(self):
        self.early_secret = None
        self.handshake_secret = None
        self.master_secret = None
        self.client_handshake_traffic_secret = None
        self.server_handshake_traffic_secret = None
        self.client_application_traffic_secret = None
        self.server_application_traffic_secret = None
        self.client_finished_key = None
        self.server_finished_key = None
        self.exporter_master_secret = None
        self.resumption_master_secret = None
        
    def derive_handshake_secrets(self, shared_secret, client_hello_random=None, server_hello_random=None):
        """RFC 8446 7.1 - Derive handshake traffic secrets
        
        Key Schedule:
        0 -> HKDF-Extract = Early Secret
            Derive-Secret(., "derived", "") = derived_secret
        
        (EC)DHE -> HKDF-Extract = Handshake Secret
            Derive-Secret(., "c hs traffic", ClientHello...ServerHello) = client_handshake_traffic_secret
            Derive-Secret(., "s hs traffic", ClientHello...ServerHello) = server_handshake_traffic_secret
        """
        
        logger.debug("Deriving handshake secrets...")
        
        if shared_secret is None:
            raise ValueError("Shared secret required for handshake derivation")
        
        # Step 1: Derive early secret (PSK not used, so use zeros)
        # Early Secret = HKDF-Extract(salt=0x00*48, IKM=0x00*48)
        self.early_secret = hkdf_extract(
            salt=b'\x00' * self.HASH_LENGTH,
            ikm=b'\x00' * self.HASH_LENGTH
        )
        logger.debug(f"Early Secret derived: {len(self.early_secret)} bytes")
        
        # Step 2: Derive derived_secret from Early Secret
        # For PSK mode transition: Derive-Secret(early_secret, "derived", "")
        derived_secret = hkdf_expand_label(
            secret=self.early_secret,
            label="derived",
            context=b"",
            length=self.HASH_LENGTH
        )
        
        # Step 3: Extract Handshake Secret
        # Handshake Secret = HKDF-Extract(salt=derived_secret, IKM=shared_secret)
        self.handshake_secret = hkdf_extract(
            salt=derived_secret,
            ikm=shared_secret
        )
        logger.debug(f"Handshake Secret derived: {len(self.handshake_secret)} bytes")
        
        # Note: For client_hs_traffic_secret and server_hs_traffic_secret,
        # the context is Transcript-Hash(ClientHello, ServerHello)
        # This should be passed via derive_handshake_secrets_with_context
        
        logger.debug("Handshake secrets extracted successfully")
    
    def derive_handshake_traffic_secrets(self, transcript_hash):
        """Derive client and server handshake traffic secrets
        
        Requires transcript hash of ClientHello...ServerHello
        """
        if self.handshake_secret is None:
            raise ValueError("Handshake secret not yet derived")
        
        # client_handshake_traffic_secret = Derive-Secret(handshake_secret, "c hs traffic", transcript_hash)
        self.client_handshake_traffic_secret = hkdf_expand_label(
            secret=self.handshake_secret,
            label="c hs traffic",
            context=transcript_hash,
            length=self.HASH_LENGTH
        )
        
        # server_handshake_traffic_secret = Derive-Secret(handshake_secret, "s hs traffic", transcript_hash)
        self.server_handshake_traffic_secret = hkdf_expand_label(
            secret=self.handshake_secret,
            label="s hs traffic",
            context=transcript_hash,
            length=self.HASH_LENGTH
        )
        
        logger.debug("Handshake traffic secrets derived")
    
    def derive_application_secrets(self, transcript_hash):
        """RFC 8446 7.1 - Derive application traffic secrets
        
        Requires transcript hash through server Finished message
        """
        
        logger.debug("Deriving application traffic secrets...")
        
        if self.handshake_secret is None:
            raise ValueError("Handshake secret not yet derived")
        
        # Step 1: Derive derived_secret from Handshake Secret
        derived_secret = hkdf_expand_label(
            secret=self.handshake_secret,
            label="derived",
            context=b"",
            length=self.HASH_LENGTH
        )
        
        # Step 2: Extract Master Secret
        # Master Secret = HKDF-Extract(salt=derived_secret, IKM=0x00*HASH_LENGTH)
        self.master_secret = hkdf_extract(
            salt=derived_secret,
            ikm=b'\x00' * self.HASH_LENGTH
        )
        logger.debug(f"Master Secret derived: {len(self.master_secret)} bytes")
        
        # Step 3: Derive client and server application traffic secrets
        # client_application_traffic_secret_0 = Derive-Secret(master_secret, "c ap traffic", transcript_hash)
        self.client_application_traffic_secret = hkdf_expand_label(
            secret=self.master_secret,
            label="c ap traffic",
            context=transcript_hash,
            length=self.HASH_LENGTH
        )
        
        # server_application_traffic_secret_0 = Derive-Secret(master_secret, "s ap traffic", transcript_hash)
        self.server_application_traffic_secret = hkdf_expand_label(
            secret=self.master_secret,
            label="s ap traffic",
            context=transcript_hash,
            length=self.HASH_LENGTH
        )
        
        # exporter_master_secret for exporters
        self.exporter_master_secret = hkdf_expand_label(
            secret=self.master_secret,
            label="exp master",
            context=transcript_hash,
            length=self.HASH_LENGTH
        )
        
        # resumption_master_secret for session resumption (for client Finished)
        self.resumption_master_secret = hkdf_expand_label(
            secret=self.master_secret,
            label="res master",
            context=transcript_hash,
            length=self.HASH_LENGTH
        )
        
        logger.debug("Application traffic secrets derived successfully")
    
    def derive_finished_keys(self, transcript_hash):
        """RFC 8446 4.4.4 - Derive Finished message keys
        
        finished_key = HKDF-Expand-Label(Secret, "finished", "", Hash.length)
        verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
        """
        
        if self.client_handshake_traffic_secret is None:
            raise ValueError("Client handshake traffic secret not yet derived")
        if self.server_handshake_traffic_secret is None:
            raise ValueError("Server handshake traffic secret not yet derived")
        
        # client_finished_key = HKDF-Expand-Label(client_handshake_traffic_secret, "finished", "", Hash.length)
        self.client_finished_key = hkdf_expand_label(
            secret=self.client_handshake_traffic_secret,
            label="finished",
            context=b"",
            length=self.HASH_LENGTH
        )
        
        # server_finished_key = HKDF-Expand-Label(server_handshake_traffic_secret, "finished", "", Hash.length)
        self.server_finished_key = hkdf_expand_label(
            secret=self.server_handshake_traffic_secret,
            label="finished",
            context=b"",
            length=self.HASH_LENGTH
        )
        
        logger.debug("Finished keys derived")
    
    def derive_traffic_keys(self, traffic_secret, key_length=None, iv_length=None):
        """RFC 8446 7.3 - Derive write_key and write_iv from traffic secret
        
        [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
        [sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
        """
        
        if key_length is None:
            key_length = self.KEY_LENGTH
        if iv_length is None:
            iv_length = self.IV_LENGTH
        
        if traffic_secret is None:
            raise ValueError("Traffic secret required")
        
        # Derive write_key
        write_key = hkdf_expand_label(
            secret=traffic_secret,
            label="key",
            context=b"",
            length=key_length
        )
        
        # Derive write_iv
        write_iv = hkdf_expand_label(
            secret=traffic_secret,
            label="iv",
            context=b"",
            length=iv_length
        )
        
        return {
            'key': write_key,
            'iv': write_iv
        }
    
    def get_client_handshake_keys(self):
        """Get client handshake phase write_key and write_iv"""
        return self.derive_traffic_keys(self.client_handshake_traffic_secret)
    
    def get_server_handshake_keys(self):
        """Get server handshake phase write_key and write_iv"""
        return self.derive_traffic_keys(self.server_handshake_traffic_secret)
    
    def get_client_application_keys(self):
        """Get client application phase write_key and write_iv"""
        return self.derive_traffic_keys(self.client_application_traffic_secret)
    
    def get_server_application_keys(self):
        """Get server application phase write_key and write_iv"""
        return self.derive_traffic_keys(self.server_application_traffic_secret)
    
    def get_client_finished_key(self):
        """Get client finished key for Finished message"""
        if self.client_finished_key is None:
            raise ValueError("Client finished key not yet derived")
        return self.client_finished_key
    
    def get_server_finished_key(self):
        """Get server finished key for Finished message"""
        if self.server_finished_key is None:
            raise ValueError("Server finished key not yet derived")
        return self.server_finished_key
    
    def update_application_traffic_secret(self, is_client=True):
        """
        Update traffic secret for key rotation (TLS 1.3 feature)
        Args:
            is_client: Whether to update client or server secret
        """
        if is_client:
            self.client_application_traffic_secret = hkdf_expand_label(
                secret=self.client_application_traffic_secret,
                label="traffic upd",
                context=b"",
                length=32
            )
        else:
            self.server_application_traffic_secret = hkdf_expand_label(
                secret=self.server_application_traffic_secret,
                label="traffic upd",
                context=b"",
                length=32
            )