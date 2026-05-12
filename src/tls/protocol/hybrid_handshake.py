"""
Hybrid Post-Quantum TLS 1.3 Handshake
X25519 + ML-KEM-768 (FIPS 203)
"""

import logging
import struct
from typing import Optional, Tuple

from .handshake import TLSHandshake, ClientHello, ServerHello
from ..crypto.pq_algorithms import HybridKeyExchange, HybridSecretCombination

logger = logging.getLogger("HybridTLSHandshake")


class HybridClientHello(ClientHello):
    """ClientHello with hybrid key share (X25519 + ML-KEM-768)"""
    
    def __init__(self):
        super().__init__()
        # Replace X25519-only key exchange with hybrid
        self.hybrid_kex = HybridKeyExchange()
        self.hybrid_pubkey = self.hybrid_kex.generate_keypair()
        
        # Override key_share extension with hybrid pubkey
        self._override_key_share_extension()
    
    def _override_key_share_extension(self):
        """Replace key_share with hybrid pubkey (X25519 32B + ML-KEM 1184B = 1216B)"""
        # Combine X25519 + ML-KEM pubkeys
        hybrid_share = self.hybrid_pubkey['x25519'] + self.hybrid_pubkey['mlkem']
        
        key_share_data = b''
        group = 0x001D  # x25519
        key_share_data += struct.pack('>H', group)
        key_share_data += struct.pack('>H', len(hybrid_share))
        key_share_data += hybrid_share
        
        shares_data = struct.pack('>H', len(key_share_data))
        shares_data += key_share_data
        
        self.extensions['key_share'] = {
            'type': self.extensions['key_share']['type'],
            'data': shares_data
        }
    
    @staticmethod
    def extract_hybrid_key_share_from_bytes(data: bytes) -> Tuple[bytes, bytes]:
        """Extract hybrid pubkey: (X25519 32B, ML-KEM 1184B)"""
        try:
            offset = 4
            offset += 2 + 32
            session_id_len = data[offset]
            offset += 1 + session_id_len
            cipher_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2 + cipher_len
            compression_len = data[offset]
            offset += 1 + compression_len
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            extensions_end = offset + extensions_len
            
            while offset < extensions_end:
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                ext_len = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                ext_data = data[offset:offset+ext_len]
                offset += ext_len
                
                if ext_type == 51:  # key_share
                    shares_len = struct.unpack('>H', ext_data[0:2])[0]
                    shares_offset = 2
                    shares_offset += 2  # skip group
                    key_len = struct.unpack('>H', ext_data[shares_offset:shares_offset+2])[0]
                    shares_offset += 2
                    hybrid_key = ext_data[shares_offset:shares_offset+key_len]
                    
                    # Split: 32B X25519 + 1184B ML-KEM
                    x25519_key = hybrid_key[:32]
                    mlkem_key = hybrid_key[32:32+1184]
                    return x25519_key, mlkem_key
            
            logger.warning("Hybrid key_share not found")
            return None, None
        except Exception as e:
            logger.error(f"Failed to extract hybrid key_share: {e}")
            return None, None


class HybridServerHello(ServerHello):
    """ServerHello with hybrid key share"""
    
    def __init__(self, client_hybrid_pubkey=None):
        super().__init__()
        self.hybrid_kex = HybridKeyExchange()
        self.hybrid_pubkey = self.hybrid_kex.generate_keypair()
        
        # Store client pubkey and encapsulation result
        self.client_hybrid_pubkey = client_hybrid_pubkey
        self.encap_result = None
        
        # Encapsulate to client if pubkey provided
        if client_hybrid_pubkey:
            self.encap_result = self.hybrid_kex.encapsulate(client_hybrid_pubkey)
        
        self._override_key_share_extension()
    
    def _override_key_share_extension(self):
        """Include server pubkeys + ML-KEM ciphertext for client"""
        hybrid_share = self.hybrid_pubkey['x25519'] + self.hybrid_pubkey['mlkem']
        
        # If we have a ciphertext, append it
        if self.encap_result:
            hybrid_share += self.encap_result['mlkem_ct']
        
        key_share_data = b''
        group = 0x001D
        key_share_data += struct.pack('>H', group)
        key_share_data += struct.pack('>H', len(hybrid_share))
        key_share_data += hybrid_share
        
        self.extensions['key_share'] = {
            'type': self.extensions['key_share']['type'],
            'data': key_share_data
        }
    
    @staticmethod
    def extract_hybrid_key_share_from_bytes(data: bytes) -> Tuple[bytes, bytes, bytes]:
        """Extract hybrid pubkey + ciphertext: (X25519 32B, ML-KEM 1184B, ciphertext 1088B)"""
        try:
            offset = 4
            offset += 2 + 32 + 1
            cipher_suite = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            compression = data[offset]
            offset += 1
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            extensions_end = offset + extensions_len
            
            while offset < extensions_end:
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                ext_len = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                ext_data = data[offset:offset+ext_len]
                offset += ext_len
                
                if ext_type == 51:  # key_share
                    # ServerHello key_share format: group (2) + key_exchange_len (2) + key_exchange
                    share_offset = 0
                    share_offset += 2  # skip group
                    key_len = struct.unpack('>H', ext_data[share_offset:share_offset+2])[0]
                    share_offset += 2
                    hybrid_key = ext_data[share_offset:share_offset+key_len]
                    
                    # Parse: 32B X25519 + 1184B ML-KEM pubkey + 1088B ciphertext
                    x25519_key = hybrid_key[:32]
                    mlkem_key = hybrid_key[32:32+1184]
                    mlkem_ct = hybrid_key[32+1184:32+1184+1088] if len(hybrid_key) > 32+1184 else b''
                    return x25519_key, mlkem_key, mlkem_ct
            
            return None, None, None
        except Exception as e:
            logger.error(f"Failed to extract hybrid key_share from ServerHello: {e}")
            return None, None, None


class HybridTLSHandshake(TLSHandshake):
    """Hybrid Post-Quantum TLS 1.3 Handshake (RFC 8446 + ML-KEM-768)"""
    
    def __init__(self, is_server: bool = False):
        super().__init__(is_server)
        self.hybrid_secret = None
        self.hybrid_combo = HybridSecretCombination()
    
    def process_client_hello(self, data: bytes) -> Tuple[Optional[bytes], bool]:
        """Server: Process hybrid ClientHello"""
        if not self.is_server:
            raise RuntimeError("ClientHello processing only on server side")
        
        logger.info("Processing Hybrid ClientHello...")
        
        self.client_hello = HybridClientHello()
        self.client_hello._raw_bytes = data
        
        # Extract hybrid pubkey
        client_x25519, client_mlkem = HybridClientHello.extract_hybrid_key_share_from_bytes(data)
        if not (client_x25519 and client_mlkem):
            logger.error("Failed to extract hybrid key_share")
            return None, False
        
        self.add_to_transcript(self.client_hello)
        
        # Server: Generate response with hybrid pubkey + encapsulation
        self.server_hello = HybridServerHello({'x25519': client_x25519, 'mlkem': client_mlkem})
        
        # Use the encapsulation result from ServerHello
        encap_result = self.server_hello.encap_result
        
        # Store secrets for later
        self.shared_secret = encap_result  # dict with x25519_ss, mlkem_ss, mlkem_ct
        
        server_hello_bytes = self.server_hello.serialize()
        self.add_to_transcript(self.server_hello)
        
        self._derive_hybrid_handshake_secrets()
        
        logger.info("Hybrid ClientHello processed")
        self.state = "SERVER_HELLO_SENT"
        
        return server_hello_bytes, False
    
    def process_server_hello(self, data: bytes) -> bool:
        """Client: Process hybrid ServerHello"""
        if self.is_server:
            raise RuntimeError("ServerHello processing only on client side")
        
        logger.info("Processing Hybrid ServerHello...")
        
        self.server_hello = HybridServerHello(None)
        self.server_hello._raw_bytes = data
        
        # Extract hybrid pubkey + ciphertext
        server_x25519, server_mlkem, mlkem_ct = HybridServerHello.extract_hybrid_key_share_from_bytes(data)
        if not (server_x25519 and server_mlkem):
            logger.error("Failed to extract hybrid key_share")
            return False
        
        self.add_to_transcript(self.server_hello)
        
        # Client: Decapsulate from server's encapsulation
        decap_result = self.client_hello.hybrid_kex.decapsulate({
            'x25519_ss': None,  # Placeholder (not used)
            'mlkem_ss': None,   # Will be decrypted
            'mlkem_ct': mlkem_ct
        })
        
        # Client also encapsulates to server
        encap_result = self.client_hello.hybrid_kex.encapsulate({
            'x25519': server_x25519,
            'mlkem': server_mlkem
        })
        
        # Combine both results
        x25519_ss = encap_result['x25519_ss']
        mlkem_ss = decap_result['mlkem_ss'] if decap_result.get('mlkem_ss') else encap_result['mlkem_ss']
        
        self.shared_secret = {
            'x25519_ss': x25519_ss,
            'mlkem_ss': mlkem_ss,
            'mlkem_ct': mlkem_ct
        }
        
        self._derive_hybrid_handshake_secrets()
        
        logger.info("Hybrid ServerHello processed")
        self.state = "HANDSHAKE_KEYS_DERIVED"
        
        return True
    
    def _derive_hybrid_handshake_secrets(self):
        """Derive secrets from hybrid key exchange"""
        if self.shared_secret is None:
            raise RuntimeError("Shared secret not computed")
        
        # Combine X25519 + ML-KEM secrets using HKDF
        x25519_ss = self.shared_secret['x25519_ss']
        mlkem_ss = self.shared_secret['mlkem_ss']
        
        combined_secret = self.hybrid_combo.combine_hkdf(x25519_ss, mlkem_ss)
        self.hybrid_secret = combined_secret
        
        logger.debug(f"Hybrid secret derived: {len(combined_secret)} bytes")
        
        # Derive handshake secrets from combined secret
        self.key_schedule.derive_handshake_secrets(
            combined_secret,
            self.client_hello.random if self.client_hello else b'',
            self.server_hello.random if self.server_hello else b''
        )
        
        handshake_context = self.compute_transcript_hash()
        self.key_schedule.derive_handshake_traffic_secrets(handshake_context)
    
    def create_client_hello(self) -> bytes:
        """Client: Create hybrid ClientHello"""
        if self.is_server:
            raise RuntimeError("ClientHello creation only on client side")
        
        logger.info("Creating Hybrid ClientHello...")
        self.client_hello = HybridClientHello()
        hello_bytes = self.client_hello.serialize()
        self.add_to_transcript(self.client_hello)
        self.state = "CLIENT_HELLO_SENT"
        return hello_bytes
